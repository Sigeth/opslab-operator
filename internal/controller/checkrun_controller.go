package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/checkerio"
)

// PodLogs reads the log of a container.
type PodLogs interface {
	Logs(ctx context.Context, namespace, pod, container string) (string, error)
}

// CheckRunReconciler runs the checker of a CheckRun as a Job in the
// instance namespace and copies its results into the CheckRun status.
//
// A run is Completed when the checker reported every requested task, and
// Error otherwise (crash, timeout, invalid or missing results): an error says
// nothing about the tasks, so a broken check never counts as solved.
type CheckRunReconciler struct {
	client.Client
	APIReader client.Reader
	Config    Config
	Logs      PodLogs
	Now       func() time.Time
}

// +kubebuilder:rbac:groups=opslab.io,resources=checkruns,verbs=get;list;watch
// +kubebuilder:rbac:groups=opslab.io,resources=checkruns/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create
// +kubebuilder:rbac:groups="",resources=pods/log,verbs=get

// Reconcile implements reconcile.Reconciler.
func (r *CheckRunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var run v1alpha1.CheckRun
	if err := r.Get(ctx, req.NamespacedName, &run); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if run.Status.Phase == v1alpha1.CheckRunCompleted || run.Status.Phase == v1alpha1.CheckRunError {
		return ctrl.Result{}, nil
	}
	before := run.Status.DeepCopy()
	result, err := r.step(ctx, &run)
	if err != nil {
		return ctrl.Result{}, err
	}
	if !apiEqual(before, &run.Status) {
		if err := r.Status().Update(ctx, &run); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
	}
	return result, nil
}

func (r *CheckRunReconciler) step(ctx context.Context, run *v1alpha1.CheckRun) (ctrl.Result, error) {
	var inst v1alpha1.ChallengeInstance
	if err := r.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: run.Spec.Instance}, &inst); err != nil {
		if apierrors.IsNotFound(err) {
			return r.error(run, "the instance does not exist")
		}
		return ctrl.Result{}, err
	}
	if inst.Status.Phase != v1alpha1.InstanceReady {
		return r.error(run, "the instance is not ready")
	}
	var ch v1alpha1.Challenge
	if err := r.Get(ctx, types.NamespacedName{Name: inst.Spec.Challenge}, &ch); err != nil || ch.Status.Package == nil {
		return r.error(run, fmt.Sprintf("challenge %q is not installed", inst.Spec.Challenge))
	}
	pkg := ch.Status.Package
	for _, task := range run.Spec.Tasks {
		if !slices.ContainsFunc(pkg.Spec.Tasks, func(t v1alpha1.Task) bool { return t.ID == task }) {
			return r.error(run, fmt.Sprintf("unknown task %q", task))
		}
	}

	ns := inst.Status.Namespace
	name := CheckJobName(run.Name)
	var job batchv1.Job
	err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &job)
	switch {
	case apierrors.IsNotFound(err):
		if run.Status.Phase != "" {
			return r.error(run, "the checker job disappeared")
		}
		var pkgFiles corev1.ConfigMap
		if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: ns, Name: PackageConfigMap}, &pkgFiles); err != nil {
			return ctrl.Result{}, err
		}
		image := r.Config.CheckerImage
		if pkg.Spec.Validation != nil && pkg.Spec.Validation.CheckerImage != "" {
			image = pkg.Spec.Validation.CheckerImage
		}
		job := checkJob(name, ns, run, image, &pkgFiles)
		if err := r.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
			return ctrl.Result{}, err
		}
		log.FromContext(ctx).Info("checker started", "job", ns+"/"+name, "image", image)
		run.Status.Phase = v1alpha1.CheckRunPending
		return ctrl.Result{RequeueAfter: CheckTimeout + 30*time.Second}, nil
	case err != nil:
		return ctrl.Result{}, err
	}

	if job.Status.StartTime != nil && run.Status.StartedAt == nil {
		run.Status.StartedAt = job.Status.StartTime
		run.Status.Phase = v1alpha1.CheckRunRunning
	}
	switch {
	case jobCondition(&job, batchv1.JobComplete):
		logs, err := r.jobLogs(ctx, &job)
		if err != nil {
			return ctrl.Result{}, err
		}
		results, err := checkerio.ParseLog(strings.NewReader(logs))
		if err != nil {
			return r.error(run, "invalid checker output: "+err.Error())
		}
		if missing := missingTasks(run, pkg, results); len(missing) > 0 {
			return r.error(run, "the checker did not report "+strings.Join(missing, ", "))
		}
		run.Status.Phase = v1alpha1.CheckRunCompleted
		run.Status.Results = results
		run.Status.CompletedAt = &metav1.Time{Time: r.now()}
		log.FromContext(ctx).Info("check completed", "results", len(results))
	case jobCondition(&job, batchv1.JobFailed):
		logs, err := r.jobLogs(ctx, &job)
		if err != nil {
			logs = err.Error()
		}
		return r.error(run, "the checker failed: "+tail([]byte(logs)))
	case r.now().Sub(run.CreationTimestamp.Time) > CheckTimeout+time.Minute:
		return r.error(run, "the checker did not finish in time")
	}
	return ctrl.Result{RequeueAfter: CheckTimeout}, nil
}

// missingTasks lists the requested tasks (all when none is requested) that
// have no result.
func missingTasks(run *v1alpha1.CheckRun, pkg *v1alpha1.ChallengePackage, results []v1alpha1.TaskResult) []string {
	want := run.Spec.Tasks
	if len(want) == 0 {
		for _, t := range pkg.Spec.Tasks {
			want = append(want, t.ID)
		}
	}
	var missing []string
	for _, id := range want {
		if !slices.ContainsFunc(results, func(r v1alpha1.TaskResult) bool { return r.Task == id }) {
			missing = append(missing, id)
		}
	}
	return missing
}

func (r *CheckRunReconciler) jobLogs(ctx context.Context, job *batchv1.Job) (string, error) {
	var pods corev1.PodList
	if err := r.APIReader.List(ctx, &pods, client.InNamespace(job.Namespace), client.MatchingLabels{"batch.kubernetes.io/job-name": job.Name}); err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pod for job %s", job.Name)
	}
	return r.Logs.Logs(ctx, job.Namespace, pods.Items[0].Name, RoleChecker)
}

func (r *CheckRunReconciler) error(run *v1alpha1.CheckRun, msg string) (ctrl.Result, error) {
	run.Status.Phase = v1alpha1.CheckRunError
	run.Status.Message = msg
	run.Status.CompletedAt = &metav1.Time{Time: r.now()}
	return ctrl.Result{}, nil
}

func (r *CheckRunReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func jobCondition(job *batchv1.Job, t batchv1.JobConditionType) bool {
	for _, c := range job.Status.Conditions {
		if c.Type == t && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// SetupWithManager registers the reconciler.
func (r *CheckRunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	owner := func(_ context.Context, obj client.Object) []reconcile.Request {
		l := obj.GetLabels()
		if l[LabelCheckRun] == "" || l[LabelInstanceNamespace] == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: l[LabelInstanceNamespace], Name: l[LabelCheckRun]}}}
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.CheckRun{}).
		Watches(&batchv1.Job{}, handler.EnqueueRequestsFromMapFunc(owner)).
		Named("checkrun").
		Complete(r)
}
