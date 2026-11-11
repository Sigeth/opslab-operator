package controller

import (
	"context"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing/fstest"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/challenge"
)

// ChallengeReconciler installs challenges: it resolves and validates the
// package, and reports whether this cluster can run it.
//
// M1 supports inline packages (local development) only.
type ChallengeReconciler struct {
	client.Client
	Config Config
}

// +kubebuilder:rbac:groups=opslab.io,resources=challenges,verbs=get;list;watch
// +kubebuilder:rbac:groups=opslab.io,resources=challenges/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=opslab.io,resources=platformconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch

// Reconcile implements reconcile.Reconciler.
func (r *ChallengeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ch v1alpha1.Challenge
	if err := r.Get(ctx, req.NamespacedName, &ch); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	platform, err := getPlatformConfig(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, err
	}

	status := ch.Status.DeepCopy()
	status.ObservedGeneration = ch.Generation
	pkg, digest, resolveErr := r.resolve(ctx, &ch)
	if resolveErr != nil {
		status.Package, status.Digest, status.Runnable = nil, "", false
		status.UnrunnableReason = ""
		setCondition(&status.Conditions, ch.Generation, metav1.ConditionFalse, "Invalid", resolveErr.Error())
	} else {
		status.Package, status.Digest = pkg, digest
		status.Mirrored = false // no registry mirror before M3
		status.UnrunnableReason = unrunnableReason(pkg, platform)
		status.Runnable = status.UnrunnableReason == ""
		setCondition(&status.Conditions, ch.Generation, metav1.ConditionTrue, "Installed",
			fmt.Sprintf("%s %s installed", pkg.Metadata.Name, pkg.Metadata.Version))
	}

	if apiEqual(&ch.Status, status) {
		return ctrl.Result{}, nil
	}
	ch.Status = *status
	if err := r.Status().Update(ctx, &ch); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	log.FromContext(ctx).Info("challenge reconciled", "installed", resolveErr == nil, "runnable", status.Runnable)
	return ctrl.Result{}, nil
}

// resolve returns the validated and defaulted package with its digest.
func (r *ChallengeReconciler) resolve(ctx context.Context, ch *v1alpha1.Challenge) (*v1alpha1.ChallengePackage, string, error) {
	src := ch.Spec.Source
	if src.Inline == nil {
		return nil, "", fmt.Errorf("only inline packages are supported by this operator version (catalog and OCI sources come with the marketplace)")
	}
	pkg := src.Inline.Package.DeepCopy()
	bundle, err := inlineFiles(ctx, r.Client, r.Config.SystemNamespace, src.Inline)
	if err != nil {
		return nil, "", err
	}
	if errs := challenge.Validate(pkg, mapFS(bundle)); len(errs) > 0 {
		return nil, "", fmt.Errorf("invalid package: %v", errs.ToAggregate())
	}
	if pkg.Metadata.Name != ch.Name {
		return nil, "", fmt.Errorf("the Challenge must be named after its package %q", pkg.Metadata.Name)
	}
	digest, err := challenge.Digest(pkg, bundle)
	if err != nil {
		return nil, "", err
	}
	challenge.SetDefaults(pkg)
	return pkg, digest, nil
}

// inlineFiles reads the files of an inline package from its ConfigMap.
func inlineFiles(ctx context.Context, c client.Reader, namespace string, inline *v1alpha1.InlinePackage) (map[string][]byte, error) {
	files := map[string][]byte{}
	if inline.FilesConfigMap == "" {
		return files, nil
	}
	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: inline.FilesConfigMap}, &cm); err != nil {
		return nil, fmt.Errorf("reading package files from ConfigMap %s/%s: %w", namespace, inline.FilesConfigMap, err)
	}
	for key, content := range cm.Data {
		files[challenge.ConfigMapPath(key)] = []byte(content)
	}
	for key, content := range cm.BinaryData {
		files[challenge.ConfigMapPath(key)] = content
	}
	return files, nil
}

func mapFS(files map[string][]byte) fs.FS {
	m := fstest.MapFS{}
	for name, content := range files {
		m[name] = &fstest.MapFile{Data: content, Mode: 0o644}
	}
	return m
}

// apiEqual compares API objects semantically (quantities, times...).
func apiEqual(a, b any) bool { return equality.Semantic.DeepEqual(a, b) }

// unrunnableReason explains why the cluster cannot run a package, or is empty.
func unrunnableReason(pkg *v1alpha1.ChallengePackage, platform *v1alpha1.PlatformConfig) string {
	var reasons []string
	for _, m := range pkg.Spec.Machines {
		switch {
		case !supported(m.Runtime):
			reasons = append(reasons, fmt.Sprintf("machine %s: the %s runtime is not supported yet", m.Name, m.Runtime))
		case len(platform.Spec.AllowedRuntimes) > 0 && !slices.Contains(platform.Spec.AllowedRuntimes, m.Runtime):
			reasons = append(reasons, fmt.Sprintf("machine %s: the %s runtime is not allowed by the platform", m.Name, m.Runtime))
		}
	}
	egress := pkg.Spec.Permissions.Egress
	allowed := platform.Spec.AllowedEgress
	if allowed == "" {
		allowed = v1alpha1.EgressNone
	}
	switch {
	case egress == v1alpha1.EgressAllowlist:
		reasons = append(reasons, "egress allowlists need FQDN network policies, not supported yet")
	case egress == v1alpha1.EgressInternet && allowed != v1alpha1.EgressInternet:
		reasons = append(reasons, "internet egress is not allowed by the platform")
	}
	if len(pkg.Spec.ExtraManifests) > 0 {
		reasons = append(reasons, "extraManifests are not supported yet")
	}
	return strings.Join(reasons, "; ")
}

// getPlatformConfig returns the PlatformConfig, or an empty one (defaults)
// when it does not exist.
func getPlatformConfig(ctx context.Context, c client.Reader) (*v1alpha1.PlatformConfig, error) {
	var pc v1alpha1.PlatformConfig
	err := c.Get(ctx, types.NamespacedName{Name: v1alpha1.PlatformConfigName}, &pc)
	if apierrors.IsNotFound(err) {
		return &v1alpha1.PlatformConfig{}, nil
	}
	return &pc, err
}

func setCondition(conds *[]metav1.Condition, generation int64, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(conds, metav1.Condition{
		Type:               v1alpha1.ConditionReady,
		Status:             status,
		ObservedGeneration: generation,
		Reason:             reason,
		Message:            message,
	})
}

// SetupWithManager registers the reconciler.
func (r *ChallengeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	all := func(ctx context.Context, _ client.Object) []reconcile.Request {
		var list v1alpha1.ChallengeList
		if err := r.List(ctx, &list); err != nil {
			return nil
		}
		reqs := make([]reconcile.Request, 0, len(list.Items))
		for _, ch := range list.Items {
			reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{Name: ch.Name}})
		}
		return reqs
	}
	usingConfigMap := func(ctx context.Context, obj client.Object) []reconcile.Request {
		var reqs []reconcile.Request
		for _, req := range all(ctx, obj) {
			var ch v1alpha1.Challenge
			if r.Get(ctx, req.NamespacedName, &ch) == nil && ch.Spec.Source.Inline != nil &&
				ch.Spec.Source.Inline.FilesConfigMap == obj.GetName() && obj.GetNamespace() == r.Config.SystemNamespace {
				reqs = append(reqs, req)
			}
		}
		return reqs
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Challenge{}).
		Watches(&v1alpha1.PlatformConfig{}, handler.EnqueueRequestsFromMapFunc(all)).
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(usingConfigMap)).
		Named("challenge").
		Complete(r)
}
