package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubevirtv1 "kubevirt.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/checkerio"
	"github.com/Sigeth/opslab-core-go/pkg/sshexec"
)

const vmManifest = `apiVersion: opslab.io/v1alpha1
kind: ChallengePackage
metadata: {name: hello, version: 0.1.0}
spec:
  title: Hello
  summary: Smallest VM challenge.
  category: linux-hardening
  difficulty: easy
  machines:
    - {name: box, runtime: vm, image: quay.io/containerdisks/debian:13, setup: [setup/setup.sh]}
  access:
    terminals: [{machine: box}]
  tasks:
    - id: hello
      title: Create /tmp/hello
      points: 1
      check: {machine: box, file: {path: /tmp/hello}}
`

var vmConfig = func() Config {
	cfg := testConfig
	cfg.Runtimes = []v1alpha1.Runtime{v1alpha1.RuntimePod, v1alpha1.RuntimeVM}
	cfg.OperatorPods = map[string]string{"app.kubernetes.io/name": "operator"}
	cfg.GatewayPods = map[string]string{"app.kubernetes.io/name": "gateway"}
	return cfg
}()

// fakeSSH answers `cloud-init status` with cloudInit (or err) and records
// the setup scripts.
type fakeSSH struct {
	cloudInit string
	err       error
	exit      int
	calls     []sshexec.Request
	stdin     []string
}

func (f *fakeSSH) Run(_ context.Context, req sshexec.Request) (sshexec.Result, error) {
	f.calls = append(f.calls, req)
	if f.err != nil {
		return sshexec.Result{}, f.err
	}
	if req.Command == "cloud-init status" {
		return sshexec.Result{Stdout: []byte(f.cloudInit)}, nil
	}
	in, _ := io.ReadAll(req.Stdin)
	f.stdin = append(f.stdin, string(in))
	return sshexec.Result{ExitCode: f.exit, Stderr: []byte("setup output")}, nil
}

func installedVM(t *testing.T) (client.Client, types.NamespacedName) {
	t.Helper()
	ch, cm := inlineChallenge(t, vmManifest)
	c := newClient(t, ch, cm)
	doReconcile(t, &ChallengeReconciler{Client: c, Config: vmConfig}, types.NamespacedName{Name: "hello"})
	if got := get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{}); !got.Status.Runnable {
		t.Fatalf("a vm challenge must be runnable with KubeVirt: %s", got.Status.UnrunnableReason)
	}
	inst := &v1alpha1.ChallengeInstance{
		ObjectMeta: metav1.ObjectMeta{Name: "hello-alice", Namespace: instancesNS, Generation: 1, CreationTimestamp: metav1.Now()},
		Spec:       v1alpha1.ChallengeInstanceSpec{Challenge: "hello", Owner: v1alpha1.InstanceOwner{UserID: "1"}},
	}
	if err := c.Create(context.Background(), inst); err != nil {
		t.Fatal(err)
	}
	return c, types.NamespacedName{Namespace: instancesNS, Name: inst.Name}
}

func setVMIPhase(t *testing.T, c client.Client, ns, name string, phase kubevirtv1.VirtualMachineInstancePhase) {
	t.Helper()
	vmi := get(t, c, types.NamespacedName{Namespace: ns, Name: name}, &kubevirtv1.VirtualMachineInstance{})
	if vmi.UID == "" {
		vmi.UID = "uid-" + types.UID(name)
		if err := c.Update(context.Background(), vmi); err != nil {
			t.Fatal(err)
		}
	}
	vmi.Status.Phase = phase
	if err := c.Status().Update(context.Background(), vmi); err != nil {
		t.Fatal(err)
	}
}

func machineMessage(t *testing.T, c client.Client, key types.NamespacedName) string {
	t.Helper()
	return get(t, c, key, &v1alpha1.ChallengeInstance{}).Status.Message
}

func TestVMInstanceResources(t *testing.T) {
	c, key := installedVM(t)
	r := &ChallengeInstanceReconciler{Client: c, APIReader: c, Config: vmConfig, SSH: &fakeSSH{}}
	doReconcile(t, r, key) // finalizer
	doReconcile(t, r, key) // provisioning
	ns := InstanceNamespace(key.Name)

	vmi := get(t, c, types.NamespacedName{Namespace: ns, Name: "box"}, &kubevirtv1.VirtualMachineInstance{})
	if vmi.Labels[LabelRole] != RoleMachine || vmi.Labels[LabelMachine] != "box" {
		t.Fatalf("labels = %v: the launcher pod needs them for the service and network policy", vmi.Labels)
	}
	if disk := vmi.Spec.Volumes[0].ContainerDisk; disk == nil || disk.Image != "quay.io/containerdisks/debian:13" {
		t.Fatalf("volumes = %+v", vmi.Spec.Volumes)
	}
	if ref := vmi.Spec.Volumes[1].CloudInitNoCloud.UserDataSecretRef.Name; ref != cloudInitSecretName("box") {
		t.Fatalf("cloud-init secret = %s", ref)
	}
	if lim := vmi.Spec.Domain.Resources.Limits[corev1.ResourceCPU]; lim.Cmp(defaultMachineCPU) != 0 {
		t.Fatalf("limits = %v: without them the LimitRange default would throttle the VM", vmi.Spec.Domain.Resources.Limits)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: "box"}, &corev1.Pod{}); err == nil {
		t.Fatal("a vm machine has no pod of its own")
	}

	// SSH material: user keys, pinned host key, known hosts by address.
	sshSecret := get(t, c, types.NamespacedName{Namespace: ns, Name: v1alpha1.SSHSecret}, &corev1.Secret{})
	access, err := parseSSHAccess(sshSecret)
	if err != nil {
		t.Fatal(err)
	}
	if known := string(sshSecret.Data[v1alpha1.SSHSecretKnownHosts]); !strings.HasPrefix(known, "box."+ns+".svc ssh-ed25519 ") {
		t.Fatalf("known_hosts = %q", known)
	}
	userData := get(t, c, types.NamespacedName{Namespace: ns, Name: cloudInitSecretName("box")}, &corev1.Secret{}).Data["userdata"]
	if !strings.HasPrefix(string(userData), "#cloud-config\n") {
		t.Fatalf("user data = %q", userData)
	}
	var config struct {
		Hostname string `json:"hostname"`
		SSHKeys  struct {
			Public string `json:"ed25519_public"`
		} `json:"ssh_keys"`
		Users []struct {
			Name string   `json:"name"`
			Keys []string `json:"ssh_authorized_keys"`
		} `json:"users"`
	}
	if err := yaml.Unmarshal(userData, &config); err != nil {
		t.Fatal(err)
	}
	if config.Hostname != "box" || config.SSHKeys.Public != access.hosts["box"].Public || len(config.Users) != 2 ||
		config.Users[0].Name != v1alpha1.StudentUser || config.Users[0].Keys[0] != access.student.Public ||
		config.Users[1].Name != v1alpha1.CheckerUser || config.Users[1].Keys[0] != access.checker.Public {
		t.Fatalf("cloud-config = %+v", config)
	}

	// The quota covers the launcher overhead; the operator may SSH in.
	quota := get(t, c, types.NamespacedName{Namespace: ns, Name: "opslab-quota"}, &corev1.ResourceQuota{})
	want := checkerMemory.DeepCopy()
	want.Add(defaultMachineMemory)
	want.Add(vmOverheadMemory)
	if got := quota.Spec.Hard[corev1.ResourceLimitsMemory]; got.Cmp(want) != 0 {
		t.Fatalf("memory quota = %s, want %s", got.String(), want.String())
	}
	policy := get(t, c, types.NamespacedName{Namespace: ns, Name: "opslab-machines"}, &networkingv1.NetworkPolicy{})
	sshRule := policy.Spec.Ingress[len(policy.Spec.Ingress)-1]
	if sshRule.Ports[0].Port.IntVal != v1alpha1.SSHPort || len(sshRule.From) != 2 ||
		sshRule.From[0].PodSelector.MatchLabels["app.kubernetes.io/name"] != "operator" ||
		sshRule.From[1].PodSelector.MatchLabels["app.kubernetes.io/name"] != "gateway" ||
		sshRule.From[1].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != testConfig.Gateway.Namespace {
		t.Fatalf("SSH ingress = %+v", sshRule)
	}

	// The checker reaches the machine over SSH.
	targetsSecret := get(t, c, types.NamespacedName{Namespace: ns, Name: TargetsSecret}, &corev1.Secret{})
	var targets checkerio.Targets
	if err := json.Unmarshal(targetsSecret.Data[TargetsKey], &targets); err != nil {
		t.Fatal(err)
	}
	if tg := targets.Machines["box"]; tg.SSHUser != v1alpha1.CheckerUser || tg.SSHPort != 22 || tg.SSHKnownHostsFile != SSHMountPath+"/known_hosts" || tg.Pod != "" {
		t.Fatalf("target = %+v", tg)
	}

	// A retried creation renders the same cloud-init data from the stored keys.
	ch := get(t, c, types.NamespacedName{Name: "hello"}, &v1alpha1.Challenge{})
	stored, err := r.sshAccessOf(context.Background(), ns)
	if err != nil {
		t.Fatal(err)
	}
	again, err := cloudInitUserData(ch.Status.Package.Spec.Machines[0], stored)
	if err != nil || string(again) != string(userData) {
		t.Fatalf("a retry would render different keys (%v)", err)
	}
}

func TestVMInstanceLifecycle(t *testing.T) {
	c, key := installedVM(t)
	ssh := &fakeSSH{err: errors.New("connection refused")}
	r := &ChallengeInstanceReconciler{Client: c, APIReader: c, Config: vmConfig, SSH: ssh, Now: time.Now}
	doReconcile(t, r, key)
	doReconcile(t, r, key)
	ns := InstanceNamespace(key.Name)

	setVMIPhase(t, c, ns, "box", kubevirtv1.Scheduled)
	doReconcile(t, r, key)
	if msg := machineMessage(t, c, key); msg != "box: starting" {
		t.Fatalf("message = %q", msg)
	}

	// Running but not reachable yet.
	setVMIPhase(t, c, ns, "box", kubevirtv1.Running)
	doReconcile(t, r, key)
	if msg := machineMessage(t, c, key); msg != "box: booting" {
		t.Fatalf("message = %q", msg)
	}

	// Reachable, cloud-init still running.
	ssh.err, ssh.cloudInit = nil, "status: running\n"
	doReconcile(t, r, key)
	if msg := machineMessage(t, c, key); msg != "box: booting (cloud-init running)" {
		t.Fatalf("message = %q", msg)
	}
	if len(ssh.stdin) != 0 {
		t.Fatal("setup must wait for cloud-init")
	}

	// cloud-init done: setup runs as root through the checker user, once.
	ssh.cloudInit = "\nstatus: done\n"
	doReconcile(t, r, key)
	inst := get(t, c, key, &v1alpha1.ChallengeInstance{})
	if inst.Status.Phase != v1alpha1.InstanceReady || !inst.Status.Machines[0].Ready || inst.Status.Machines[0].Pod != "" {
		t.Fatalf("status = %+v", inst.Status)
	}
	last := ssh.calls[len(ssh.calls)-1]
	if last.Command != "sudo -n sh -s" || last.User != v1alpha1.CheckerUser || last.Addr != "box."+ns+".svc:22" ||
		!strings.HasPrefix(string(last.KnownHosts), "box."+ns+".svc ") || len(ssh.stdin) != 1 || ssh.stdin[0] != "echo broken > /tmp/state\n" {
		t.Fatalf("setup call = %+v, stdin %q", last, ssh.stdin)
	}
	calls := len(ssh.calls)
	doReconcile(t, r, key)
	if len(ssh.calls) != calls {
		t.Fatal("a set up machine must not be probed again")
	}

	// A stopped VM fails the instance.
	setVMIPhase(t, c, ns, "box", kubevirtv1.Failed)
	doReconcile(t, r, key)
	if inst := get(t, c, key, &v1alpha1.ChallengeInstance{}); inst.Status.Phase != v1alpha1.InstanceFailed || !strings.Contains(inst.Status.Message, "stopped") {
		t.Fatalf("status = %+v", inst.Status)
	}
}

func TestVMCloudInitErrorFails(t *testing.T) {
	c, key := installedVM(t)
	r := &ChallengeInstanceReconciler{Client: c, APIReader: c, Config: vmConfig, SSH: &fakeSSH{cloudInit: "status: error\n"}}
	doReconcile(t, r, key)
	doReconcile(t, r, key)
	setVMIPhase(t, c, InstanceNamespace(key.Name), "box", kubevirtv1.Running)
	doReconcile(t, r, key)
	if inst := get(t, c, key, &v1alpha1.ChallengeInstance{}); inst.Status.Phase != v1alpha1.InstanceFailed || !strings.Contains(inst.Status.Message, "cloud-init failed") {
		t.Fatalf("status = %+v", inst.Status)
	}
}

func TestVMSetupFailureFails(t *testing.T) {
	c, key := installedVM(t)
	r := &ChallengeInstanceReconciler{Client: c, APIReader: c, Config: vmConfig, SSH: &fakeSSH{cloudInit: "status: done\n", exit: 2}}
	doReconcile(t, r, key)
	doReconcile(t, r, key)
	setVMIPhase(t, c, InstanceNamespace(key.Name), "box", kubevirtv1.Running)
	doReconcile(t, r, key)
	if inst := get(t, c, key, &v1alpha1.ChallengeInstance{}); inst.Status.Phase != v1alpha1.InstanceFailed || !strings.Contains(inst.Status.Message, "exited with 2") {
		t.Fatalf("status = %+v", inst.Status)
	}
}

func TestCheckJobMountsSSHForVM(t *testing.T) {
	run := &v1alpha1.CheckRun{ObjectMeta: metav1.ObjectMeta{Name: "run", Namespace: instancesNS}}
	job := checkJob("check-run", "inst-a", run, "checker:test", &corev1.ConfigMap{}, true)
	pod := job.Spec.Template.Spec
	var ssh *corev1.Volume
	for i := range pod.Volumes {
		if pod.Volumes[i].Name == "ssh" {
			ssh = &pod.Volumes[i]
		}
	}
	if ssh == nil || ssh.Secret.SecretName != v1alpha1.SSHSecret || len(ssh.Secret.Items) != 3 {
		t.Fatalf("ssh volume = %+v", ssh)
	}
	for _, item := range ssh.Secret.Items {
		if strings.HasPrefix(item.Key, sshHostKeyPrefix) {
			t.Fatal("the checker must not get the machines' private host keys")
		}
	}
	if m := pod.Containers[0].VolumeMounts; m[len(m)-1].MountPath != SSHMountPath {
		t.Fatalf("mounts = %+v", m)
	}
	if job := checkJob("check-run", "inst-a", run, "checker:test", &corev1.ConfigMap{}, false); len(job.Spec.Template.Spec.Volumes) != 2 {
		t.Fatal("pod-only instances mount no SSH keys")
	}
}

func TestCloudInitStatus(t *testing.T) {
	for out, want := range map[string]string{
		"status: done\n": "done", "\nstatus: running": "running", "status: error\ndetail: x": "error", "": "unknown",
	} {
		if got := cloudInitStatus([]byte(out)); got != want {
			t.Errorf("cloudInitStatus(%q) = %q, want %q", out, got, want)
		}
	}
}
