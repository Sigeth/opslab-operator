package controller

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kubevirtv1 "kubevirt.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/project"
	"github.com/Sigeth/opslab-core-go/pkg/sshexec"
)

// vm machines are KubeVirt VirtualMachineInstances: ephemeral like a bare
// pod, never restarted. Any containerDisk meeting the base image contract
// works (D32): the users and keys come from cloud-init at boot.

// Overhead of a VM's launcher pod (QEMU, libvirt, console log) on top of the
// guest, counted in the namespace quota. About 430Mi for a 1 CPU / 1Gi guest
// with KubeVirt 1.9, growing slowly with vCPUs and memory.
var (
	vmOverheadCPU    = resource.MustParse("100m")
	vmOverheadMemory = resource.MustParse("512Mi")
)

// sshHostKeyPrefix prefixes the keys of the SSH Secret holding the private
// host key of each vm machine, kept so a retried provisioning renders the
// same cloud-init data.
const sshHostKeyPrefix = "host-"

// vmProbeTimeout bounds one SSH command checking a machine's boot.
const vmProbeTimeout = 15 * time.Second

// sshAccess is the SSH material of an instance.
type sshAccess struct {
	student, checker sshexec.Key
	hosts            map[string]sshexec.Key // by machine
}

func hasVM(pkg *v1alpha1.ChallengePackage) bool {
	for _, m := range pkg.Spec.Machines {
		if m.Runtime == v1alpha1.RuntimeVM {
			return true
		}
	}
	return false
}

// newSSHAccess generates the keys of an instance, or nil without vm machines.
func newSSHAccess(pkg *v1alpha1.ChallengePackage) (*sshAccess, error) {
	if !hasVM(pkg) {
		return nil, nil
	}
	a := &sshAccess{hosts: map[string]sshexec.Key{}}
	var err error
	if a.student, err = sshexec.GenerateKey(); err != nil {
		return nil, err
	}
	if a.checker, err = sshexec.GenerateKey(); err != nil {
		return nil, err
	}
	for _, m := range pkg.Spec.Machines {
		if m.Runtime == v1alpha1.RuntimeVM {
			if a.hosts[m.Name], err = sshexec.GenerateKey(); err != nil {
				return nil, err
			}
		}
	}
	return a, nil
}

// parseSSHAccess reads back the material of an existing SSH Secret.
func parseSSHAccess(s *corev1.Secret) (*sshAccess, error) {
	parse := func(key string) (sshexec.Key, error) {
		k, err := sshexec.ParseKey(s.Data[key])
		if err != nil {
			return k, fmt.Errorf("secret %s, key %s: %w", s.Name, key, err)
		}
		return k, nil
	}
	a := &sshAccess{hosts: map[string]sshexec.Key{}}
	var err error
	if a.student, err = parse(v1alpha1.SSHSecretStudentKey); err != nil {
		return nil, err
	}
	if a.checker, err = parse(v1alpha1.SSHSecretCheckerKey); err != nil {
		return nil, err
	}
	for key := range s.Data {
		if machine, ok := strings.CutPrefix(key, sshHostKeyPrefix); ok {
			if a.hosts[machine], err = parse(key); err != nil {
				return nil, err
			}
		}
	}
	return a, nil
}

// secret renders the SSH Secret of an instance namespace.
func (a *sshAccess) secret(ns string) (*corev1.Secret, error) {
	data := map[string][]byte{
		v1alpha1.SSHSecretStudentKey: a.student.Private,
		v1alpha1.SSHSecretCheckerKey: a.checker.Private,
	}
	var known strings.Builder
	for _, machine := range sortedMachines(a.hosts) {
		host := a.hosts[machine]
		data[sshHostKeyPrefix+machine] = host.Private
		line, err := sshexec.KnownHostsLine(machineAddress(machine, ns), host.Public)
		if err != nil {
			return nil, err
		}
		known.WriteString(line + "\n")
	}
	data[v1alpha1.SSHSecretKnownHosts] = []byte(known.String())
	return &corev1.Secret{Data: data}, nil
}

func sortedMachines(m map[string]sshexec.Key) []string { return slices.Sorted(maps.Keys(m)) }

func cloudInitSecretName(machine string) string { return dnsName(machine+"-", "cloud-init") }

// cloudInitUserData creates the student and checker users with their keys,
// installs the pinned host key, and disables passwords. The student gets
// bash when the image has it.
func cloudInitUserData(m v1alpha1.Machine, a *sshAccess) ([]byte, error) {
	host := a.hosts[m.Name]
	sudo := "ALL=(ALL) NOPASSWD:ALL"
	config := map[string]any{
		"hostname":          m.Name,
		"preserve_hostname": false,
		"manage_etc_hosts":  true,
		"disable_root":      true,
		"ssh_pwauth":        false,
		"ssh_deletekeys":    true,
		// Only the pinned key below: nothing else is generated (the schema
		// refuses an empty list).
		"ssh_genkeytypes": []string{"ed25519"},
		"ssh_keys": map[string]string{
			"ed25519_private": string(host.Private),
			"ed25519_public":  host.Public,
		},
		// No "default" entry: the distribution's default user is not created.
		"users": []map[string]any{
			{
				"name": v1alpha1.StudentUser, "uid": machineUID, "lock_passwd": true, "sudo": sudo,
				"ssh_authorized_keys": []string{a.student.Public},
			},
			{
				"name": v1alpha1.CheckerUser, "lock_passwd": true, "sudo": sudo, "shell": "/bin/sh",
				"ssh_authorized_keys": []string{a.checker.Public},
			},
		},
		"runcmd": []string{"if [ -x /bin/bash ]; then usermod -s /bin/bash " + v1alpha1.StudentUser + "; fi"},
	}
	data, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	return append([]byte("#cloud-config\n"), data...), nil
}

func cloudInitSecret(meta metav1.ObjectMeta, m v1alpha1.Machine, a *sshAccess) (*corev1.Secret, error) {
	userData, err := cloudInitUserData(m, a)
	if err != nil {
		return nil, err
	}
	meta.Name = cloudInitSecretName(m.Name)
	return &corev1.Secret{ObjectMeta: meta, Data: map[string][]byte{"userdata": userData}}, nil
}

// machineVMI runs a vm machine. Its labels reach the launcher pod, so the
// machine Service and network policy apply to it as to pod machines.
func machineVMI(meta metav1.ObjectMeta, m v1alpha1.Machine) *kubevirtv1.VirtualMachineInstance {
	meta.Labels = withLabels(withLabels(meta.Labels, LabelMachine, m.Name), LabelRole, RoleMachine)
	cpu, memory := machineResources(m)
	resources := corev1.ResourceList{corev1.ResourceCPU: cpu, corev1.ResourceMemory: memory}
	virtio := kubevirtv1.DiskDevice{Disk: &kubevirtv1.DiskTarget{Bus: kubevirtv1.DiskBusVirtio}}
	return &kubevirtv1.VirtualMachineInstance{
		ObjectMeta: meta,
		Spec: kubevirtv1.VirtualMachineInstanceSpec{
			Hostname:                      m.Name,
			NodeSelector:                  map[string]string{corev1.LabelArchStable: project.Arch, corev1.LabelOSStable: project.OS},
			TerminationGracePeriodSeconds: new(int64(5)),
			Domain: kubevirtv1.DomainSpec{
				Resources: kubevirtv1.ResourceRequirements{Requests: resources, Limits: resources.DeepCopy()},
				// The default graphics device stays: without one, Debian's
				// cloud image reboots in a loop at GRUB.
				Devices: kubevirtv1.Devices{
					Disks: []kubevirtv1.Disk{
						{Name: "root", DiskDevice: virtio},
						{Name: "cloud-init", DiskDevice: virtio},
					},
					Interfaces: []kubevirtv1.Interface{{
						Name:                   "default",
						InterfaceBindingMethod: kubevirtv1.InterfaceBindingMethod{Masquerade: &kubevirtv1.InterfaceMasquerade{}},
					}},
				},
			},
			Networks: []kubevirtv1.Network{{Name: "default", NetworkSource: kubevirtv1.NetworkSource{Pod: &kubevirtv1.PodNetwork{}}}},
			Volumes: []kubevirtv1.Volume{
				{Name: "root", VolumeSource: kubevirtv1.VolumeSource{ContainerDisk: &kubevirtv1.ContainerDiskSource{
					Image: m.Image, ImagePullPolicy: corev1.PullIfNotPresent,
				}}},
				{Name: "cloud-init", VolumeSource: kubevirtv1.VolumeSource{CloudInitNoCloud: &kubevirtv1.CloudInitNoCloudSource{
					UserDataSecretRef: &corev1.LocalObjectReference{Name: cloudInitSecretName(m.Name)},
				}}},
			},
		},
	}
}

// sshAccessOf returns the stored SSH material of an instance namespace, or
// nil when it does not exist yet.
func (r *ChallengeInstanceReconciler) sshAccessOf(ctx context.Context, ns string) (*sshAccess, error) {
	var s corev1.Secret
	err := r.APIReader.Get(ctx, types.NamespacedName{Namespace: ns, Name: v1alpha1.SSHSecret}, &s)
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseSSHAccess(&s)
}

// vmMachine reports whether a vm machine is ready: running, reachable over
// SSH as the checker user with its pinned host key, cloud-init done, and its
// setup scripts run.
func (r *ChallengeInstanceReconciler) vmMachine(ctx context.Context, vmi *kubevirtv1.VirtualMachineInstance, m v1alpha1.Machine, pkg *v1alpha1.ChallengePackage) (bool, string, error) {
	switch vmi.Status.Phase {
	case kubevirtv1.Failed, kubevirtv1.Succeeded:
		return false, "", &fatalError{fmt.Sprintf("machine %s stopped (%s)", m.Name, vmi.Status.Phase)}
	case kubevirtv1.Running:
	case kubevirtv1.Scheduled:
		return false, "starting", nil
	default:
		return false, vmiWaiting(vmi), nil
	}
	if done, ok := vmi.Annotations[AnnotationSetupDone]; ok && done == string(vmi.UID) {
		return true, "", nil
	}

	access, err := r.sshAccessOf(ctx, vmi.Namespace)
	if err != nil {
		return false, "", err
	}
	if access == nil {
		return false, "", &fatalError{fmt.Sprintf("machine %s: the %s secret is missing", m.Name, v1alpha1.SSHSecret)}
	}
	secret, err := access.secret(vmi.Namespace)
	if err != nil {
		return false, "", err
	}
	run := func(timeout time.Duration, command string, stdin []byte) (sshexec.Result, error) {
		rctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req := sshexec.Request{
			Addr:       net.JoinHostPort(machineAddress(m.Name, vmi.Namespace), strconv.Itoa(int(v1alpha1.SSHPort))),
			User:       v1alpha1.CheckerUser,
			PrivateKey: access.checker.Private,
			KnownHosts: secret.Data[v1alpha1.SSHSecretKnownHosts],
			Command:    command,
		}
		if stdin != nil {
			req.Stdin = strings.NewReader(string(stdin))
		}
		return r.SSH.Run(rctx, req)
	}

	res, err := run(vmProbeTimeout, "cloud-init status", nil)
	if err != nil {
		// Booting: sshd or the users are not there yet.
		log.FromContext(ctx).V(1).Info("machine not reachable yet", "machine", m.Name, "error", err.Error())
		return false, "booting", nil
	}
	switch status := cloudInitStatus(res.Stdout); status {
	case "done":
	case "error":
		return false, "", &fatalError{fmt.Sprintf("machine %s: cloud-init failed: %s", m.Name, tail(res.Stdout, res.Stderr))}
	default:
		return false, "booting (cloud-init " + status + ")", nil
	}

	if len(m.Setup) > 0 {
		files, err := r.packageFiles(ctx, vmi.Namespace)
		if err != nil {
			return false, "", err
		}
		for _, script := range m.Setup {
			content, err := fs.ReadFile(files, script)
			if err != nil {
				return false, "", &fatalError{fmt.Sprintf("machine %s: setup %s: %v", m.Name, script, err)}
			}
			log.FromContext(ctx).Info("running setup", "machine", m.Name, "script", script)
			res, err := run(SetupTimeout, "sudo -n sh -s", content)
			if err != nil {
				return false, "", fmt.Errorf("machine %s: setup %s: %w", m.Name, script, err)
			}
			if res.ExitCode != 0 {
				return false, "", &fatalError{fmt.Sprintf("machine %s: setup %s exited with %d: %s", m.Name, script, res.ExitCode, tail(res.Stderr, res.Stdout))}
			}
		}
	}

	patch := client.MergeFrom(vmi.DeepCopy())
	if vmi.Annotations == nil {
		vmi.Annotations = map[string]string{}
	}
	vmi.Annotations[AnnotationSetupDone] = string(vmi.UID)
	if err := r.Patch(ctx, vmi, patch); err != nil {
		return false, "", err
	}
	return true, "", nil
}

// cloudInitStatus extracts the status from `cloud-init status` ("done",
// "running", "not started", "error"...).
func cloudInitStatus(out []byte) string {
	for line := range strings.SplitSeq(string(out), "\n") {
		if s, ok := strings.CutPrefix(strings.TrimSpace(line), "status:"); ok {
			return strings.TrimSpace(s)
		}
	}
	return "unknown"
}

// vmiWaiting explains why a VMI is not running yet.
func vmiWaiting(vmi *kubevirtv1.VirtualMachineInstance) string {
	for _, c := range vmi.Status.Conditions {
		if c.Status == corev1.ConditionFalse && c.Message != "" {
			return fmt.Sprintf("%s: %s", c.Reason, c.Message)
		}
	}
	if vmi.Status.Phase == "" {
		return "creating"
	}
	return strings.ToLower(string(vmi.Status.Phase))
}
