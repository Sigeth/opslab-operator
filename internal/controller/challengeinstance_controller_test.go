package controller

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
)

func TestNewInstancesAreQueued(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	instance := &v1alpha1.ChallengeInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "hello-alice", Namespace: "opslab-instances", Generation: 1},
		Spec:       v1alpha1.ChallengeInstanceSpec{Challenge: "hello-shell", Owner: v1alpha1.InstanceOwner{UserID: "1"}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(instance).WithStatusSubresource(instance).Build()
	r := &ChallengeInstanceReconciler{Client: c}
	key := types.NamespacedName{Name: "hello-alice", Namespace: "opslab-instances"}

	for range 2 { // reconciling twice must be idempotent
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
	}

	var got v1alpha1.ChallengeInstance
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != v1alpha1.InstanceQueued || got.Status.ObservedGeneration != 1 {
		t.Fatalf("status = %+v", got.Status)
	}
}

func TestDeletedInstancesAreIgnored(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	r := &ChallengeInstanceReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "gone", Namespace: "opslab-instances"}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}
