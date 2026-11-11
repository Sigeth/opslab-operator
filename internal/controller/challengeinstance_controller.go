// Package controller contains the opslab reconcilers.
package controller

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
)

// ChallengeInstanceReconciler drives a ChallengeInstance through its
// lifecycle: Queued → Provisioning → Ready → Expired (or Failed).
//
// M0 only admits new instances into the Queued phase; provisioning comes in M1.
type ChallengeInstanceReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups=opslab.io,resources=challengeinstances,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=opslab.io,resources=challengeinstances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=opslab.io,resources=challenges,verbs=get;list;watch

// Reconcile implements reconcile.Reconciler.
func (r *ChallengeInstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var instance v1alpha1.ChallengeInstance
	if err := r.Get(ctx, req.NamespacedName, &instance); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if instance.Status.Phase != "" {
		return ctrl.Result{}, nil
	}

	log.FromContext(ctx).Info("admitting instance", "challenge", instance.Spec.Challenge, "owner", instance.Spec.Owner.UserID)
	instance.Status.Phase = v1alpha1.InstanceQueued
	instance.Status.ObservedGeneration = instance.Generation
	instance.Status.Message = "waiting for capacity"
	if err := r.Status().Update(ctx, &instance); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler.
func (r *ChallengeInstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ChallengeInstance{}).
		Named("challengeinstance").
		Complete(r)
}
