// Package controller contains the opslab reconcilers.
package controller

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/kubeexec"
)

// ChallengeInstanceReconciler drives a ChallengeInstance through its
// lifecycle: Provisioning → Ready → Expired, or Failed.
//
// Provisioning creates the namespace inst-<name> (quota, limits, network
// policy, checker credentials), one Pod and headless Service per machine, then
// runs each machine's setup scripts. Deleting the instance, or reaching its
// expiry, deletes the namespace: everything in it is lost.
//
// Capacity admission (the Queued phase) is not implemented yet: instances are
// provisioned right away.
type ChallengeInstanceReconciler struct {
	client.Client
	// APIReader reads objects the cache does not hold (ConfigMaps of
	// instance namespaces).
	APIReader client.Reader
	Config    Config
	// Exec runs setup scripts in machines.
	Exec kubeexec.Executor
	// Now returns the current time (overridden in tests).
	Now func() time.Time
}

// +kubebuilder:rbac:groups=opslab.io,resources=challengeinstances,verbs=get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=opslab.io,resources=challengeinstances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=opslab.io,resources=challengeinstances/finalizers,verbs=update
// +kubebuilder:rbac:groups=opslab.io,resources=challenges,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;create;delete;patch
// +kubebuilder:rbac:groups="",resources=pods/exec,verbs=create;get
// +kubebuilder:rbac:groups="",resources=services;configmaps;secrets;serviceaccounts;resourcequotas;limitranges,verbs=create
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=create
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=create
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=bind

// Reconcile implements reconcile.Reconciler.
func (r *ChallengeInstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var inst v1alpha1.ChallengeInstance
	if err := r.Get(ctx, req.NamespacedName, &inst); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !inst.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, &inst)
	}
	if !controllerutil.ContainsFinalizer(&inst, Finalizer) {
		controllerutil.AddFinalizer(&inst, Finalizer)
		return ctrl.Result{}, r.Update(ctx, &inst)
	}

	before := inst.Status.DeepCopy()
	result, err := r.step(ctx, &inst)
	if err != nil {
		return ctrl.Result{}, err
	}
	inst.Status.ObservedGeneration = inst.Generation
	setInstanceCondition(&inst)
	if !apiEqual(before, &inst.Status) {
		if err := r.Status().Update(ctx, &inst); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
	}
	return result, nil
}

// step advances the instance by one phase and updates its status in memory.
func (r *ChallengeInstanceReconciler) step(ctx context.Context, inst *v1alpha1.ChallengeInstance) (ctrl.Result, error) {
	now := r.now()
	switch inst.Status.Phase {
	case v1alpha1.InstanceExpired, v1alpha1.InstanceFailed:
		return r.terminated(ctx, inst, now)
	}

	ch, err := r.challenge(ctx, inst)
	if err != nil {
		return r.fail(ctx, inst, err.Error())
	}
	platform, err := getPlatformConfig(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}
	pkg := ch.Status.Package
	inst.Status.ExpiresAt = &metav1.Time{Time: expiry(inst, pkg, platform)}
	if !now.Before(inst.Status.ExpiresAt.Time) {
		return r.expire(ctx, inst, now)
	}

	if inst.Status.Phase == "" || inst.Status.Phase == v1alpha1.InstanceQueued {
		log.FromContext(ctx).Info("provisioning instance", "challenge", ch.Name, "owner", inst.Spec.Owner.UserID)
		inst.Status.Phase = v1alpha1.InstanceProvisioning
		inst.Status.Namespace = InstanceNamespace(inst.Name)
		inst.Status.ChallengeDigest = ch.Status.Digest
		inst.Status.Message = "creating the machines"
		if err := r.create(ctx, ch, pkg, inst); err != nil {
			return r.fail(ctx, inst, err.Error())
		}
	}

	ready, err := r.machines(ctx, inst, pkg, now)
	if err != nil {
		var fatal *fatalError
		if errors.As(err, &fatal) {
			return r.fail(ctx, inst, fatal.Error())
		}
		return ctrl.Result{}, err
	}
	expiresIn := inst.Status.ExpiresAt.Sub(now)
	if !ready {
		if now.Sub(inst.CreationTimestamp.Time) > ProvisioningTimeout {
			return r.fail(ctx, inst, "provisioning timed out: "+inst.Status.Message)
		}
		return ctrl.Result{RequeueAfter: min(5*time.Second, expiresIn)}, nil
	}
	if inst.Status.Phase != v1alpha1.InstanceReady {
		inst.Status.Phase = v1alpha1.InstanceReady
		inst.Status.ReadyAt = &metav1.Time{Time: now}
		inst.Status.Message = ""
		log.FromContext(ctx).Info("instance ready", "namespace", inst.Status.Namespace)
	}
	return ctrl.Result{RequeueAfter: expiresIn}, nil
}

// challenge returns the installed, runnable challenge of an instance.
func (r *ChallengeInstanceReconciler) challenge(ctx context.Context, inst *v1alpha1.ChallengeInstance) (*v1alpha1.Challenge, error) {
	var ch v1alpha1.Challenge
	if err := r.Get(ctx, types.NamespacedName{Name: inst.Spec.Challenge}, &ch); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("challenge %q is not installed", inst.Spec.Challenge)
		}
		return nil, err
	}
	switch {
	case ch.Status.Package == nil || !meta.IsStatusConditionTrue(ch.Status.Conditions, v1alpha1.ConditionReady):
		return nil, fmt.Errorf("challenge %q is not ready", ch.Name)
	case !ch.Status.Runnable:
		return nil, fmt.Errorf("challenge %q cannot run on this cluster: %s", ch.Name, ch.Status.UnrunnableReason)
	case ch.Spec.Disabled && inst.Status.Phase == "":
		return nil, fmt.Errorf("challenge %q is disabled", ch.Name)
	case inst.Status.ChallengeDigest != "" && inst.Status.ChallengeDigest != ch.Status.Digest:
		// Without a registry the old version is gone (OCI packages will keep
		// running instances on their digest).
		if inst.Status.Phase != v1alpha1.InstanceReady {
			return nil, fmt.Errorf("challenge %q changed during provisioning", ch.Name)
		}
	}
	return &ch, nil
}

// expiry is the requested expiry (or creation + default lifetime), capped by
// the package's and the platform's maximum lifetimes.
func expiry(inst *v1alpha1.ChallengeInstance, pkg *v1alpha1.ChallengePackage, platform *v1alpha1.PlatformConfig) time.Time {
	created := inst.CreationTimestamp.Time
	at := created.Add(pkg.Spec.Lifetime.Default.Duration)
	if inst.Spec.ExpiresAt != nil {
		at = inst.Spec.ExpiresAt.Time
	}
	limit := pkg.Spec.Lifetime.Max.Duration
	if m := platform.Spec.MaxInstanceLifetime; m != nil && m.Duration < limit {
		limit = m.Duration
	}
	if latest := created.Add(limit); at.After(latest) {
		at = latest
	}
	return at.Truncate(time.Second)
}

// create creates the namespace and everything in it. Existing objects are
// kept: instance resources never change after creation.
func (r *ChallengeInstanceReconciler) create(ctx context.Context, ch *v1alpha1.Challenge, pkg *v1alpha1.ChallengePackage, inst *v1alpha1.ChallengeInstance) error {
	files, err := inlineFiles(ctx, r.Client, r.Config.SystemNamespace, ch.Spec.Source.Inline)
	if err != nil {
		return err
	}
	objs, err := instanceResources(r.Config, inst, pkg, files)
	if err != nil {
		return err
	}
	for _, obj := range append([]client.Object{instanceNamespace(inst)}, objs...) {
		if err := r.Create(ctx, obj); err != nil && !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("creating %T %s: %w", obj, obj.GetName(), err)
		}
	}
	return nil
}

// fatalError makes the instance fail instead of being retried.
type fatalError struct{ msg string }

func (e *fatalError) Error() string { return e.msg }

// machines updates the machine statuses, runs pending setups, and reports
// whether every machine is ready.
func (r *ChallengeInstanceReconciler) machines(ctx context.Context, inst *v1alpha1.ChallengeInstance, pkg *v1alpha1.ChallengePackage, now time.Time) (bool, error) {
	ns := inst.Status.Namespace
	statuses := make([]v1alpha1.MachineStatus, 0, len(pkg.Spec.Machines))
	var waiting []string
	for _, m := range pkg.Spec.Machines {
		st := v1alpha1.MachineStatus{Name: m.Name, Runtime: m.Runtime, Address: machineAddress(m.Name, ns), Pod: m.Name}
		var pod corev1.Pod
		err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: m.Name}, &pod)
		switch {
		case apierrors.IsNotFound(err):
			if inst.Status.Phase == v1alpha1.InstanceReady {
				return false, &fatalError{fmt.Sprintf("machine %s was deleted", m.Name)}
			}
			waiting = append(waiting, m.Name+": creating")
		case err != nil:
			return false, err
		default:
			ready, why, err := r.machine(ctx, &pod, m, pkg)
			if err != nil {
				return false, err
			}
			st.Ready = ready
			if !ready {
				waiting = append(waiting, m.Name+": "+why)
			}
		}
		statuses = append(statuses, st)
	}
	inst.Status.Machines = statuses
	if len(waiting) > 0 {
		inst.Status.Message = strings.Join(waiting, "; ")
	}
	return len(waiting) == 0, nil
}

// machine reports whether a machine pod is ready, running its setup first
// when its container has not been set up yet.
func (r *ChallengeInstanceReconciler) machine(ctx context.Context, pod *corev1.Pod, m v1alpha1.Machine, pkg *v1alpha1.ChallengePackage) (bool, string, error) {
	if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
		return false, "", &fatalError{fmt.Sprintf("machine %s stopped (%s)", m.Name, pod.Status.Phase)}
	}
	var cs *corev1.ContainerStatus
	for i := range pod.Status.ContainerStatuses {
		if pod.Status.ContainerStatuses[i].Name == v1alpha1.MachineContainer {
			cs = &pod.Status.ContainerStatuses[i]
		}
	}
	switch {
	case cs == nil:
		return false, "scheduling", nil
	case cs.State.Waiting != nil:
		if bad := cs.State.Waiting.Reason; bad == "ErrImagePull" || bad == "ImagePullBackOff" || bad == "InvalidImageName" || bad == "CreateContainerConfigError" {
			return false, fmt.Sprintf("%s: %s", bad, cs.State.Waiting.Message), nil
		}
		return false, "starting", nil
	case cs.State.Running == nil || !cs.Ready:
		return false, "starting", nil
	case pod.Annotations[AnnotationSetupDone] == cs.ContainerID:
		return true, "", nil
	}

	if err := r.setup(ctx, pod, m, pkg); err != nil {
		return false, "", err
	}
	patch := client.MergeFrom(pod.DeepCopy())
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[AnnotationSetupDone] = cs.ContainerID
	if err := r.Patch(ctx, pod, patch); err != nil {
		return false, "", err
	}
	return true, "", nil
}

// setup runs the machine's setup scripts in order, as the container user.
func (r *ChallengeInstanceReconciler) setup(ctx context.Context, pod *corev1.Pod, m v1alpha1.Machine, pkg *v1alpha1.ChallengePackage) error {
	if len(m.Setup) == 0 {
		return nil
	}
	var cm corev1.ConfigMap
	if err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: pod.Namespace, Name: PackageConfigMap}, &cm); err != nil {
		return err
	}
	files := mapFS(configMapFiles(&cm))
	for _, script := range m.Setup {
		content, err := fs.ReadFile(files, script)
		if err != nil {
			return &fatalError{fmt.Sprintf("machine %s: setup %s: %v", m.Name, script, err)}
		}
		log.FromContext(ctx).Info("running setup", "machine", m.Name, "script", script)
		sctx, cancel := context.WithTimeout(ctx, SetupTimeout)
		res, err := r.Exec.Exec(sctx, kubeexec.Request{
			Namespace: pod.Namespace,
			Pod:       pod.Name,
			Container: v1alpha1.MachineContainer,
			Command:   []string{"/bin/sh", "-s"},
			Stdin:     strings.NewReader(string(content)),
		})
		cancel()
		if err != nil {
			return fmt.Errorf("machine %s: setup %s: %w", m.Name, script, err)
		}
		if res.ExitCode != 0 {
			return &fatalError{fmt.Sprintf("machine %s: setup %s exited with %d: %s", m.Name, script, res.ExitCode, tail(res.Stderr, res.Stdout))}
		}
	}
	return nil
}

func configMapFiles(cm *corev1.ConfigMap) map[string][]byte {
	files := map[string][]byte{}
	for key, content := range cm.Data {
		files[strings.ReplaceAll(key, "__", "/")] = []byte(content)
	}
	for key, content := range cm.BinaryData {
		files[strings.ReplaceAll(key, "__", "/")] = content
	}
	return files
}

// tail returns the end of the first non-empty output, for error messages.
func tail(outputs ...[]byte) string {
	const max = 500
	for _, out := range outputs {
		if s := strings.TrimSpace(string(out)); s != "" {
			if len(s) > max {
				s = "…" + s[len(s)-max:]
			}
			return s
		}
	}
	return "no output"
}

func (r *ChallengeInstanceReconciler) fail(ctx context.Context, inst *v1alpha1.ChallengeInstance, msg string) (ctrl.Result, error) {
	log.FromContext(ctx).Info("instance failed", "reason", msg)
	inst.Status.Phase = v1alpha1.InstanceFailed
	inst.Status.Message = msg
	return r.terminated(ctx, inst, r.now())
}

func (r *ChallengeInstanceReconciler) expire(ctx context.Context, inst *v1alpha1.ChallengeInstance, now time.Time) (ctrl.Result, error) {
	log.FromContext(ctx).Info("instance expired")
	inst.Status.Phase = v1alpha1.InstanceExpired
	inst.Status.Message = "the instance reached its expiry and was deleted"
	return r.terminated(ctx, inst, now)
}

// terminated tears the environment down and deletes the instance once it has
// been visible long enough.
func (r *ChallengeInstanceReconciler) terminated(ctx context.Context, inst *v1alpha1.ChallengeInstance, now time.Time) (ctrl.Result, error) {
	inst.Status.Machines = nil
	if err := r.deleteNamespace(ctx, inst); err != nil {
		return ctrl.Result{}, err
	}
	end := now
	if c := meta.FindStatusCondition(inst.Status.Conditions, v1alpha1.ConditionReady); c != nil && c.Status == metav1.ConditionFalse && c.Reason == string(inst.Status.Phase) {
		end = c.LastTransitionTime.Time
	}
	if wait := end.Add(TerminatedRetention).Sub(now); wait > 0 {
		return ctrl.Result{RequeueAfter: wait}, nil
	}
	return ctrl.Result{}, client.IgnoreNotFound(r.Delete(ctx, inst))
}

func (r *ChallengeInstanceReconciler) deleteNamespace(ctx context.Context, inst *v1alpha1.ChallengeInstance) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: InstanceNamespace(inst.Name)}}
	return client.IgnoreNotFound(r.Delete(ctx, ns, client.PropagationPolicy(metav1.DeletePropagationBackground)))
}

func (r *ChallengeInstanceReconciler) finalize(ctx context.Context, inst *v1alpha1.ChallengeInstance) error {
	if !controllerutil.ContainsFinalizer(inst, Finalizer) {
		return nil
	}
	if err := r.deleteNamespace(ctx, inst); err != nil {
		return err
	}
	controllerutil.RemoveFinalizer(inst, Finalizer)
	return r.Update(ctx, inst)
}

func setInstanceCondition(inst *v1alpha1.ChallengeInstance) {
	status := metav1.ConditionFalse
	if inst.Status.Phase == v1alpha1.InstanceReady {
		status = metav1.ConditionTrue
	}
	msg := inst.Status.Message
	if msg == "" {
		msg = string(inst.Status.Phase)
	}
	meta.SetStatusCondition(&inst.Status.Conditions, metav1.Condition{
		Type:               v1alpha1.ConditionReady,
		Status:             status,
		ObservedGeneration: inst.Generation,
		Reason:             string(inst.Status.Phase),
		Message:            msg,
	})
}

func (r *ChallengeInstanceReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the reconciler.
func (r *ChallengeInstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	owner := func(_ context.Context, obj client.Object) []reconcile.Request {
		l := obj.GetLabels()
		if l[LabelInstance] == "" || l[LabelInstanceNamespace] == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: l[LabelInstanceNamespace], Name: l[LabelInstance]}}}
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ChallengeInstance{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(owner)).
		WithOptions(controller.Options{MaxConcurrentReconciles: 4}).
		Named("challengeinstance").
		Complete(r)
}
