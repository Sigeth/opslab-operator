package controller

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/challenge"
	"github.com/Sigeth/opslab-core-go/pkg/kubeexec"
)

const (
	systemNS    = "opslab-system"
	instancesNS = "opslab-instances"
)

var testConfig = Config{
	SystemNamespace: systemNS,
	CheckerImage:    "checker:test",
	Gateway:         types.NamespacedName{Namespace: systemNS, Name: "opslab-gateway"},
	GatewayExecRole: "opslab-gateway-exec",
	CheckerExecRole: "opslab-checker-exec",
}

const testManifest = `apiVersion: opslab.io/v1alpha1
kind: ChallengePackage
metadata: {name: hello, version: 0.1.0}
spec:
  title: Hello
  summary: Smallest challenge.
  category: linux-hardening
  difficulty: easy
  machines:
    - {name: box, runtime: pod, image: debian:13-slim, setup: [setup/setup.sh]}
  access:
    terminals: [{machine: box}]
  tasks:
    - id: hello
      title: Create /tmp/hello
      points: 1
      check: {machine: box, file: {path: /tmp/hello}}
    - id: port
      title: Listen on 8080
      points: 2
      check: {machine: box, port: {port: 8080, expect: open}}
`

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func newClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(objs...).
		WithStatusSubresource(&v1alpha1.Challenge{}, &v1alpha1.ChallengeInstance{}, &v1alpha1.CheckRun{}, &corev1.Pod{}, &batchv1.Job{}).Build()
}

func inlineChallenge(t *testing.T, manifest string) (*v1alpha1.Challenge, *corev1.ConfigMap) {
	t.Helper()
	pkg, err := challenge.Parse([]byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "challenge-hello-files", Namespace: systemNS},
		Data:       map[string]string{"setup__setup.sh": "echo broken > /tmp/state\n", "instructions__en.md": "# Hello\n"},
	}
	ch := &v1alpha1.Challenge{
		ObjectMeta: metav1.ObjectMeta{Name: pkg.Metadata.Name, Generation: 1},
		Spec: v1alpha1.ChallengeSpec{Source: v1alpha1.ChallengeSource{
			Inline: &v1alpha1.InlinePackage{Package: *pkg, FilesConfigMap: cm.Name},
		}},
	}
	return ch, cm
}

func doReconcile(t *testing.T, r interface {
	Reconcile(context.Context, ctrl.Request) (ctrl.Result, error)
}, key types.NamespacedName) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func get[T client.Object](t *testing.T, c client.Client, key types.NamespacedName, obj T) T {
	t.Helper()
	if err := c.Get(context.Background(), key, obj); err != nil {
		t.Fatal(err)
	}
	return obj
}

func TestChallengeInstall(t *testing.T) {
	ch, cm := inlineChallenge(t, testManifest)
	c := newClient(t, ch, cm)
	r := &ChallengeReconciler{Client: c, Config: testConfig}
	key := types.NamespacedName{Name: "hello"}
	doReconcile(t, r, key)

	got := get(t, c, key, &v1alpha1.Challenge{})
	st := got.Status
	if !meta.IsStatusConditionTrue(st.Conditions, v1alpha1.ConditionReady) || !st.Runnable || !strings.HasPrefix(st.Digest, "sha256:") {
		t.Fatalf("status = %+v", st)
	}
	if st.Package == nil || st.Package.Spec.Lifetime == nil || st.Package.Spec.Access.Terminals[0].User != "student" {
		t.Fatal("the package must be defaulted")
	}

	// A missing setup script makes the package invalid.
	cm.Data = map[string]string{}
	if err := c.Update(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	doReconcile(t, r, key)
	got = get(t, c, key, &v1alpha1.Challenge{})
	if cond := meta.FindStatusCondition(got.Status.Conditions, v1alpha1.ConditionReady); cond.Status != metav1.ConditionFalse || !strings.Contains(cond.Message, "setup/setup.sh") {
		t.Fatalf("condition = %+v", cond)
	}
}

func TestChallengeUnrunnable(t *testing.T) {
	manifest := strings.Replace(testManifest, "runtime: pod", "runtime: vm", 1)
	ch, cm := inlineChallenge(t, manifest)
	platform := &v1alpha1.PlatformConfig{ObjectMeta: metav1.ObjectMeta{Name: v1alpha1.PlatformConfigName}}
	c := newClient(t, ch, cm, platform)
	doReconcile(t, &ChallengeReconciler{Client: c, Config: testConfig}, types.NamespacedName{Name: "hello"})
	got := get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{})
	if got.Status.Runnable || !strings.Contains(got.Status.UnrunnableReason, "vm runtime") {
		t.Fatalf("status = %+v", got.Status)
	}
}

// fakeExec records the commands run in machines.
type fakeExec struct {
	calls []kubeexec.Request
	stdin []string
	exit  int
}

func (f *fakeExec) Exec(_ context.Context, req kubeexec.Request) (kubeexec.Result, error) {
	f.calls = append(f.calls, req)
	in, _ := io.ReadAll(req.Stdin)
	f.stdin = append(f.stdin, string(in))
	return kubeexec.Result{ExitCode: f.exit, Stderr: []byte("setup output")}, nil
}

// installed returns a client holding an installed challenge and a new instance.
func installed(t *testing.T) (client.Client, types.NamespacedName) {
	t.Helper()
	ch, cm := inlineChallenge(t, testManifest)
	c := newClient(t, ch, cm)
	doReconcile(t, &ChallengeReconciler{Client: c, Config: testConfig}, types.NamespacedName{Name: "hello"})
	inst := &v1alpha1.ChallengeInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "hello-alice", Namespace: instancesNS, Generation: 1, CreationTimestamp: metav1.Now()},
		Spec:       v1alpha1.ChallengeInstanceSpec{Challenge: "hello", Owner: v1alpha1.InstanceOwner{UserID: "1"}},
	}
	if err := c.Create(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	return c, types.NamespacedName{Namespace: instancesNS, Name: inst.Name}
}

func startPod(t *testing.T, c client.Client, ns, name, containerID string) {
	t.Helper()
	pod := get(t, c, types.NamespacedName{Namespace: ns, Name: name}, &corev1.Pod{})
	pod.Status = corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
		Name: v1alpha1.MachineContainer, Ready: true, ContainerID: containerID,
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	}}}
	if err := c.Status().Update(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
}

func TestInstanceLifecycle(t *testing.T) {
	c, key := installed(t)
	exec := &fakeExec{}
	now := time.Now()
	r := &ChallengeInstanceReconciler{Client: c, APIReader: c, Config: testConfig, Exec: exec, Now: func() time.Time { return now }}

	doReconcile(t, r, key) // finalizer
	doReconcile(t, r, key) // provisioning
	inst := get(t, c, key, &v1alpha1.ChallengeInstance{})
	ns := InstanceNamespace(key.Name)
	if inst.Status.Phase != v1alpha1.InstanceProvisioning || inst.Status.Namespace != ns || inst.Status.ChallengeDigest == "" {
		t.Fatalf("status = %+v", inst.Status)
	}
	if want := inst.CreationTimestamp.Add(time.Hour).Truncate(time.Second); !inst.Status.ExpiresAt.Time.Equal(want) {
		t.Fatalf("expiresAt = %v, want %v", inst.Status.ExpiresAt, want)
	}

	nsObj := get(t, c, types.NamespacedName{Name: ns}, &corev1.Namespace{})
	if nsObj.Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
		t.Fatalf("namespace labels = %v", nsObj.Labels)
	}
	pod := get(t, c, types.NamespacedName{Namespace: ns, Name: "box"}, &corev1.Pod{})
	sc := pod.Spec.SecurityContext
	if !*sc.RunAsNonRoot || *pod.Spec.AutomountServiceAccountToken || pod.Spec.Containers[0].Image != "debian:13-slim" {
		t.Fatalf("pod spec = %+v", pod.Spec)
	}
	get(t, c, types.NamespacedName{Namespace: ns, Name: "box"}, &corev1.Service{})
	get(t, c, types.NamespacedName{Namespace: ns, Name: "opslab-machines"}, &networkingv1.NetworkPolicy{})
	gw := get(t, c, types.NamespacedName{Namespace: ns, Name: "opslab-gateway"}, &rbacv1.RoleBinding{})
	if gw.Subjects[0].Namespace != systemNS || gw.RoleRef.Name != "opslab-gateway-exec" {
		t.Fatalf("gateway binding = %+v", gw)
	}
	pkgFiles := get(t, c, types.NamespacedName{Namespace: ns, Name: PackageConfigMap}, &corev1.ConfigMap{})
	if _, ok := pkgFiles.Data["challenge.yaml"]; !ok {
		t.Fatal("the checker needs the manifest")
	}

	// The pod starts: setup runs once, then the instance is ready.
	startPod(t, c, ns, "box", "containerd://abc")
	doReconcile(t, r, key)
	inst = get(t, c, key, &v1alpha1.ChallengeInstance{})
	if inst.Status.Phase != v1alpha1.InstanceReady || len(inst.Status.Machines) != 1 || !inst.Status.Machines[0].Ready {
		t.Fatalf("status = %+v", inst.Status)
	}
	if m := inst.Status.Machines[0]; m.Pod != "box" || m.Address != "box."+ns+".svc" {
		t.Fatalf("machine = %+v", m)
	}
	if len(exec.calls) != 1 || exec.stdin[0] != "echo broken > /tmp/state\n" || exec.calls[0].Container != v1alpha1.MachineContainer {
		t.Fatalf("exec = %+v %q", exec.calls, exec.stdin)
	}
	doReconcile(t, r, key)
	if len(exec.calls) != 1 {
		t.Fatal("setup must run once per container")
	}

	// A restarted container is set up again.
	startPod(t, c, ns, "box", "containerd://def")
	doReconcile(t, r, key)
	if len(exec.calls) != 2 {
		t.Fatal("setup must run again after a container restart")
	}

	// Expiry deletes the namespace.
	now = inst.Status.ExpiresAt.Add(time.Second)
	doReconcile(t, r, key)
	inst = get(t, c, key, &v1alpha1.ChallengeInstance{})
	if inst.Status.Phase != v1alpha1.InstanceExpired {
		t.Fatalf("phase = %s", inst.Status.Phase)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: ns}, &corev1.Namespace{}); !apierrors.IsNotFound(err) {
		t.Fatalf("namespace still exists: %v", err)
	}
}

func TestInstanceSetupFailure(t *testing.T) {
	c, key := installed(t)
	r := &ChallengeInstanceReconciler{Client: c, APIReader: c, Config: testConfig, Exec: &fakeExec{exit: 3}}
	doReconcile(t, r, key)
	doReconcile(t, r, key)
	startPod(t, c, InstanceNamespace(key.Name), "box", "containerd://abc")
	doReconcile(t, r, key)
	inst := get(t, c, key, &v1alpha1.ChallengeInstance{})
	if inst.Status.Phase != v1alpha1.InstanceFailed || !strings.Contains(inst.Status.Message, "exited with 3: setup output") {
		t.Fatalf("status = %+v", inst.Status)
	}
}

func TestInstanceOfUnknownChallengeFails(t *testing.T) {
	inst := &v1alpha1.ChallengeInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: instancesNS, Finalizers: []string{Finalizer}, CreationTimestamp: metav1.Now()},
		Spec:       v1alpha1.ChallengeInstanceSpec{Challenge: "nope", Owner: v1alpha1.InstanceOwner{UserID: "1"}},
	}
	c := newClient(t, inst)
	key := types.NamespacedName{Namespace: instancesNS, Name: "x"}
	res := doReconcile(t, &ChallengeInstanceReconciler{Client: c, APIReader: c, Config: testConfig}, key)
	got := get(t, c, key, &v1alpha1.ChallengeInstance{})
	if got.Status.Phase != v1alpha1.InstanceFailed || !strings.Contains(got.Status.Message, "not installed") || res.RequeueAfter == 0 {
		t.Fatalf("status = %+v, result = %+v", got.Status, res)
	}
}

func TestInstanceDeletionRemovesNamespace(t *testing.T) {
	c, key := installed(t)
	r := &ChallengeInstanceReconciler{Client: c, APIReader: c, Config: testConfig, Exec: &fakeExec{}}
	doReconcile(t, r, key)
	doReconcile(t, r, key)
	if err := c.Delete(context.Background(), get(t, c, key, &v1alpha1.ChallengeInstance{})); err != nil {
		t.Fatal(err)
	}
	doReconcile(t, r, key)
	if err := c.Get(context.Background(), key, &v1alpha1.ChallengeInstance{}); !apierrors.IsNotFound(err) {
		t.Fatalf("instance still exists: %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: InstanceNamespace(key.Name)}, &corev1.Namespace{}); !apierrors.IsNotFound(err) {
		t.Fatalf("namespace still exists: %v", err)
	}
}

type fakeLogs string

func (f fakeLogs) Logs(context.Context, string, string, string) (string, error) { return string(f), nil }

// readyInstance returns a client with a Ready instance and a CheckRun.
func readyInstance(t *testing.T, tasks ...string) (client.Client, types.NamespacedName) {
	t.Helper()
	c, key := installed(t)
	r := &ChallengeInstanceReconciler{Client: c, APIReader: c, Config: testConfig, Exec: &fakeExec{}}
	doReconcile(t, r, key)
	doReconcile(t, r, key)
	startPod(t, c, InstanceNamespace(key.Name), "box", "containerd://abc")
	doReconcile(t, r, key)
	run := &v1alpha1.CheckRun{
		ObjectMeta: metav1.ObjectMeta{Name: "hello-alice-1", Namespace: instancesNS, CreationTimestamp: metav1.Now()},
		Spec:       v1alpha1.CheckRunSpec{Instance: key.Name, Tasks: tasks},
	}
	if err := c.Create(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	return c, types.NamespacedName{Namespace: instancesNS, Name: run.Name}
}

func finishJob(t *testing.T, c client.Client, ns, name string, condition batchv1.JobConditionType) {
	t.Helper()
	job := get(t, c, types.NamespacedName{Namespace: ns, Name: name}, &batchv1.Job{})
	job.Status.StartTime = &metav1.Time{Time: time.Now()}
	job.Status.Conditions = []batchv1.JobCondition{{Type: condition, Status: corev1.ConditionTrue}}
	if err := c.Status().Update(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name + "-x", Namespace: ns, Labels: map[string]string{"batch.kubernetes.io/job-name": name}}}
	if err := c.Create(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
}

func TestCheckRunCompleted(t *testing.T) {
	c, key := readyInstance(t)
	logs := "checking 2 tasks\n" +
		`{"task":"hello","passed":true,"message":"found"}` + "\n" +
		`{"task":"port","passed":false,"message":"port 8080 is not reachable"}` + "\n"
	r := &CheckRunReconciler{Client: c, APIReader: c, Config: testConfig, Logs: fakeLogs(logs)}
	doReconcile(t, r, key)

	ns := InstanceNamespace("hello-alice")
	jobName := CheckJobName(key.Name)
	job := get(t, c, types.NamespacedName{Namespace: ns, Name: jobName}, &batchv1.Job{})
	ctr := job.Spec.Template.Spec.Containers[0]
	if ctr.Image != "checker:test" || job.Spec.Template.Spec.ServiceAccountName != CheckerSA {
		t.Fatalf("job = %+v", job.Spec.Template.Spec)
	}
	items := job.Spec.Template.Spec.Volumes[0].ConfigMap.Items
	if len(items) == 0 || !containsPath(items, "setup/setup.sh") || !containsPath(items, "challenge.yaml") {
		t.Fatalf("package items = %+v", items)
	}
	if get(t, c, key, &v1alpha1.CheckRun{}).Status.Phase != v1alpha1.CheckRunPending {
		t.Fatal("expected Pending")
	}

	finishJob(t, c, ns, jobName, batchv1.JobComplete)
	doReconcile(t, r, key)
	st := get(t, c, key, &v1alpha1.CheckRun{}).Status
	if st.Phase != v1alpha1.CheckRunCompleted || len(st.Results) != 2 || !st.Results[0].Passed || st.Results[1].Passed {
		t.Fatalf("status = %+v", st)
	}
}

func TestCheckRunMissingResultIsAnError(t *testing.T) {
	c, key := readyInstance(t)
	r := &CheckRunReconciler{Client: c, APIReader: c, Config: testConfig, Logs: fakeLogs(`{"task":"hello","passed":true}`)}
	doReconcile(t, r, key)
	finishJob(t, c, InstanceNamespace("hello-alice"), CheckJobName(key.Name), batchv1.JobComplete)
	doReconcile(t, r, key)
	st := get(t, c, key, &v1alpha1.CheckRun{}).Status
	if st.Phase != v1alpha1.CheckRunError || !strings.Contains(st.Message, "port") {
		t.Fatalf("status = %+v", st)
	}
}

func TestCheckRunFailedJob(t *testing.T) {
	c, key := readyInstance(t, "hello")
	r := &CheckRunReconciler{Client: c, APIReader: c, Config: testConfig, Logs: fakeLogs("checker error: boom")}
	doReconcile(t, r, key)
	finishJob(t, c, InstanceNamespace("hello-alice"), CheckJobName(key.Name), batchv1.JobFailed)
	doReconcile(t, r, key)
	st := get(t, c, key, &v1alpha1.CheckRun{}).Status
	if st.Phase != v1alpha1.CheckRunError || !strings.Contains(st.Message, "boom") {
		t.Fatalf("status = %+v", st)
	}
}

func TestCheckRunUnknownTask(t *testing.T) {
	c, key := readyInstance(t, "nope")
	doReconcile(t, &CheckRunReconciler{Client: c, APIReader: c, Config: testConfig}, key)
	if st := get(t, c, key, &v1alpha1.CheckRun{}).Status; st.Phase != v1alpha1.CheckRunError {
		t.Fatalf("status = %+v", st)
	}
}

func TestDNSNames(t *testing.T) {
	long := strings.Repeat("a", 70)
	if n := InstanceNamespace(long); len(n) != 63 || n == InstanceNamespace(long+"b") {
		t.Fatalf("namespace %q", n)
	}
	if n := InstanceNamespace("hello-alice"); n != "inst-hello-alice" {
		t.Fatalf("namespace %q", n)
	}
}

func containsPath(items []corev1.KeyToPath, path string) bool {
	for _, it := range items {
		if it.Path == path {
			return true
		}
	}
	return false
}
