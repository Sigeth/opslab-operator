package controller

import (
	"encoding/json"
	"fmt"
	"sort"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/challenge"
	"github.com/Sigeth/opslab-core-go/pkg/checkerio"
	"github.com/Sigeth/opslab-core-go/pkg/project"
)

// Default resources of machines that declare none, and of checkers.
var (
	defaultMachineCPU    = resource.MustParse("250m")
	defaultMachineMemory = resource.MustParse("256Mi")
	checkerCPU           = resource.MustParse("100m")
	checkerMemory        = resource.MustParse("128Mi")
)

// instanceResources builds every object of an instance namespace except the
// namespace itself, in creation order. access holds the SSH material of vm
// machines (nil without any); its Secret comes before what depends on it.
func instanceResources(cfg Config, inst *v1alpha1.ChallengeInstance, pkg *v1alpha1.ChallengePackage, files map[string][]byte, access *sshAccess) ([]client.Object, error) {
	ns := InstanceNamespace(inst.Name)
	labels := instanceLabels(inst)
	meta := func(name string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels}
	}

	pkgFiles, err := packageConfigMap(pkg, files)
	if err != nil {
		return nil, err
	}
	pkgFiles.ObjectMeta = meta(PackageConfigMap)
	targets, err := targetsSecret(pkg, ns)
	if err != nil {
		return nil, err
	}
	targets.ObjectMeta = meta(TargetsSecret)

	objs := []client.Object{
		&corev1.ResourceQuota{ObjectMeta: meta("opslab-quota"), Spec: quota(pkg)},
		&corev1.LimitRange{ObjectMeta: meta("opslab-limits"), Spec: corev1.LimitRangeSpec{Limits: []corev1.LimitRangeItem{{
			Type:           corev1.LimitTypeContainer,
			Default:        corev1.ResourceList{corev1.ResourceCPU: checkerCPU, corev1.ResourceMemory: checkerMemory},
			DefaultRequest: corev1.ResourceList{corev1.ResourceCPU: checkerCPU, corev1.ResourceMemory: checkerMemory},
		}}}},
		&networkingv1.NetworkPolicy{ObjectMeta: meta("opslab-machines"), Spec: machinesNetworkPolicy(cfg, pkg)},
		pkgFiles,
		targets,
		&corev1.ServiceAccount{ObjectMeta: meta(CheckerSA)},
		roleBinding(meta(CheckerSA), cfg.CheckerExecRole, rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: CheckerSA, Namespace: ns}),
		roleBinding(meta("opslab-gateway"), cfg.GatewayExecRole, rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: cfg.Gateway.Name, Namespace: cfg.Gateway.Namespace}),
	}
	if access != nil {
		secret, err := access.secret(ns)
		if err != nil {
			return nil, err
		}
		secret.ObjectMeta = meta(v1alpha1.SSHSecret)
		objs = append(objs, secret)
	}
	for _, m := range pkg.Spec.Machines {
		objs = append(objs, machineService(meta(m.Name), m))
		if m.Runtime != v1alpha1.RuntimeVM {
			objs = append(objs, machinePod(meta(m.Name), m))
			continue
		}
		if access == nil {
			return nil, fmt.Errorf("machine %s: no SSH material for a vm machine", m.Name)
		}
		userData, err := cloudInitSecret(meta(m.Name), m, access)
		if err != nil {
			return nil, err
		}
		objs = append(objs, userData, machineVMI(meta(m.Name), m))
	}
	return objs, nil
}

func instanceLabels(inst *v1alpha1.ChallengeInstance) map[string]string {
	return map[string]string{
		LabelManagedBy:         ManagedBy,
		LabelInstance:          inst.Name,
		LabelInstanceNamespace: inst.Namespace,
	}
}

// instanceNamespace is the namespace of an instance. Its pods run under the
// "restricted" Pod Security Standard.
func instanceNamespace(inst *v1alpha1.ChallengeInstance) *corev1.Namespace {
	labels := instanceLabels(inst)
	for _, mode := range []string{"enforce", "audit", "warn"} {
		labels["pod-security.kubernetes.io/"+mode] = "restricted"
	}
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: InstanceNamespace(inst.Name), Labels: labels}}
}

func machineResources(m v1alpha1.Machine) (cpu, memory resource.Quantity) {
	if m.Resources != nil {
		return m.Resources.CPU, m.Resources.Memory
	}
	return defaultMachineCPU, defaultMachineMemory
}

// quota caps the namespace at the machines (with the launcher overhead of
// VMs) plus one running checker.
func quota(pkg *v1alpha1.ChallengePackage) corev1.ResourceQuotaSpec {
	cpu, memory := checkerCPU.DeepCopy(), checkerMemory.DeepCopy()
	for _, m := range pkg.Spec.Machines {
		c, mem := machineResources(m)
		cpu.Add(c)
		memory.Add(mem)
		if m.Runtime == v1alpha1.RuntimeVM {
			cpu.Add(vmOverheadCPU)
			memory.Add(vmOverheadMemory)
		}
	}
	return corev1.ResourceQuotaSpec{Hard: corev1.ResourceList{
		corev1.ResourcePods:                   *resource.NewQuantity(int64(len(pkg.Spec.Machines)+2), resource.DecimalSI),
		corev1.ResourceRequestsCPU:            cpu,
		corev1.ResourceLimitsCPU:              cpu,
		corev1.ResourceRequestsMemory:         memory,
		corev1.ResourceLimitsMemory:           memory,
		corev1.ResourceServicesNodePorts:      resource.MustParse("0"),
		corev1.ResourceServicesLoadBalancers:  resource.MustParse("0"),
		corev1.ResourcePersistentVolumeClaims: resource.MustParse("0"),
	}}
}

// machinesNetworkPolicy isolates the machines: they reach each other and DNS,
// and only the machines and the checker reach them, plus the operator (setup)
// and the gateway (terminals) over SSH when there are vm machines. Internet egress, when the
// package asks for it, excludes private ranges (the cluster and its nodes).
// Terminals and pod setup go through the API server (exec), not the network.
func machinesNetworkPolicy(cfg Config, pkg *v1alpha1.ChallengePackage) networkingv1.NetworkPolicySpec {
	machines := metav1.LabelSelector{MatchLabels: map[string]string{LabelRole: RoleMachine}}
	checker := metav1.LabelSelector{MatchLabels: map[string]string{LabelRole: RoleChecker}}
	udp, tcp := corev1.ProtocolUDP, corev1.ProtocolTCP
	dns := intstr.FromInt32(53)
	spec := networkingv1.NetworkPolicySpec{
		PodSelector: machines,
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
		Ingress: []networkingv1.NetworkPolicyIngressRule{{
			From: []networkingv1.NetworkPolicyPeer{{PodSelector: &machines}, {PodSelector: &checker}},
		}},
		Egress: []networkingv1.NetworkPolicyEgressRule{
			{To: []networkingv1.NetworkPolicyPeer{{PodSelector: &machines}}},
			{
				To: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
				}},
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &udp, Port: &dns}, {Protocol: &tcp, Port: &dns}},
			},
		},
	}
	if hasVM(pkg) {
		var peers []networkingv1.NetworkPolicyPeer
		for _, p := range []struct {
			namespace string
			pods      map[string]string
		}{{cfg.SystemNamespace, cfg.OperatorPods}, {cfg.Gateway.Namespace, cfg.GatewayPods}} {
			if len(p.pods) > 0 {
				peers = append(peers, networkingv1.NetworkPolicyPeer{
					NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": p.namespace}},
					PodSelector:       &metav1.LabelSelector{MatchLabels: p.pods},
				})
			}
		}
		if len(peers) > 0 {
			ssh := intstr.FromInt32(v1alpha1.SSHPort)
			spec.Ingress = append(spec.Ingress, networkingv1.NetworkPolicyIngressRule{
				From:  peers,
				Ports: []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &ssh}},
			})
		}
	}
	if pkg.Spec.Permissions != nil && pkg.Spec.Permissions.Egress == v1alpha1.EgressInternet {
		spec.Egress = append(spec.Egress, networkingv1.NetworkPolicyEgressRule{
			To: []networkingv1.NetworkPolicyPeer{{IPBlock: &networkingv1.IPBlock{
				CIDR:   "0.0.0.0/0",
				Except: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"},
			}}},
		})
	}
	return spec
}

func roleBinding(meta metav1.ObjectMeta, clusterRole string, subject rbacv1.Subject) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: meta,
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: clusterRole},
		Subjects:   []rbacv1.Subject{subject},
	}
}

// machineService gives the machine a stable DNS name: <machine>.<namespace>.svc.
func machineService(meta metav1.ObjectMeta, m v1alpha1.Machine) *corev1.Service {
	meta.Labels = withLabels(meta.Labels, LabelMachine, m.Name)
	return &corev1.Service{
		ObjectMeta: meta,
		Spec: corev1.ServiceSpec{
			ClusterIP:                corev1.ClusterIPNone,
			Selector:                 map[string]string{LabelMachine: m.Name, LabelRole: RoleMachine},
			PublishNotReadyAddresses: true,
		},
	}
}

// machinePod runs a pod machine under the restricted Pod Security Standard,
// as UID/GID 1000. Stdin and a TTY keep shell entrypoints (bash, sh) alive
// without a command; images with a service entrypoint run it.
func machinePod(meta metav1.ObjectMeta, m v1alpha1.Machine) *corev1.Pod {
	meta.Labels = withLabels(withLabels(meta.Labels, LabelMachine, m.Name), LabelRole, RoleMachine)
	cpu, memory := machineResources(m)
	uid := machineUID
	return &corev1.Pod{
		ObjectMeta: meta,
		Spec: corev1.PodSpec{
			Hostname:                      m.Name,
			AutomountServiceAccountToken:  new(false),
			EnableServiceLinks:            new(false),
			TerminationGracePeriodSeconds: new(int64(5)),
			NodeSelector:                  map[string]string{corev1.LabelArchStable: project.Arch, corev1.LabelOSStable: project.OS},
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   new(true),
				RunAsUser:      &uid,
				RunAsGroup:     &uid,
				FSGroup:        &uid,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:            v1alpha1.MachineContainer,
				Image:           m.Image,
				ImagePullPolicy: corev1.PullIfNotPresent,
				Stdin:           true,
				TTY:             true,
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: cpu, corev1.ResourceMemory: memory},
					Limits:   corev1.ResourceList{corev1.ResourceCPU: cpu, corev1.ResourceMemory: memory},
				},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: new(false),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
			}},
		},
	}
}

// packageConfigMap holds the files the checker reads: the defaulted manifest
// and the package files.
func packageConfigMap(pkg *v1alpha1.ChallengePackage, files map[string][]byte) (*corev1.ConfigMap, error) {
	manifest, err := json.Marshal(pkg) // JSON is YAML: the checker parses it as challenge.yaml
	if err != nil {
		return nil, err
	}
	all := map[string][]byte{challenge.ManifestFile: manifest}
	for name, content := range files {
		if name != challenge.ManifestFile {
			all[name] = content
		}
	}
	data, binaryData, err := challenge.ConfigMapData(all)
	if err != nil {
		return nil, err
	}
	return &corev1.ConfigMap{Data: data, BinaryData: binaryData}, nil
}

// targetsSecret tells the checker how to reach each machine.
func targetsSecret(pkg *v1alpha1.ChallengePackage, ns string) (*corev1.Secret, error) {
	targets := checkerio.Targets{Machines: map[string]checkerio.Target{}}
	for _, m := range pkg.Spec.Machines {
		if m.Runtime == v1alpha1.RuntimeVM {
			targets.Machines[m.Name] = checkerio.Target{
				Runtime:               m.Runtime,
				Host:                  machineAddress(m.Name, ns),
				SSHPort:               v1alpha1.SSHPort,
				SSHUser:               v1alpha1.CheckerUser,
				SSHPrivateKeyFile:     SSHMountPath + "/" + v1alpha1.SSHSecretCheckerKey,
				SSHKnownHostsFile:     SSHMountPath + "/" + v1alpha1.SSHSecretKnownHosts,
				StudentPrivateKeyFile: SSHMountPath + "/" + v1alpha1.SSHSecretStudentKey,
			}
			continue
		}
		targets.Machines[m.Name] = checkerio.Target{
			Runtime:   m.Runtime,
			Host:      machineAddress(m.Name, ns),
			Namespace: ns,
			Pod:       m.Name,
			Container: v1alpha1.MachineContainer,
		}
	}
	data, err := json.Marshal(targets)
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{Data: map[string][]byte{TargetsKey: data}}, nil
}

func machineAddress(machine, ns string) string { return machine + "." + ns + ".svc" }

// checkJob runs the checker for a CheckRun. With vm machines, it mounts the
// users' SSH keys and the known hosts (not the machines' private host keys).
func checkJob(name, ns string, run *v1alpha1.CheckRun, image string, pkgFiles *corev1.ConfigMap, vm bool) *batchv1.Job {
	labels := map[string]string{
		LabelManagedBy:         ManagedBy,
		LabelCheckRun:          run.Name,
		LabelInstanceNamespace: run.Namespace,
		LabelRole:              RoleChecker,
	}
	// Restore the package tree from the flat ConfigMap keys.
	var items []corev1.KeyToPath
	for _, key := range sortedKeys(pkgFiles.Data, pkgFiles.BinaryData) {
		items = append(items, corev1.KeyToPath{Key: key, Path: challenge.ConfigMapPath(key)})
	}
	uid := int64(65532)
	tasks := ""
	for i, t := range run.Spec.Tasks {
		if i > 0 {
			tasks += ","
		}
		tasks += t
	}
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels},
		Spec: batchv1.JobSpec{
			BackoffLimit:            new(int32(0)),
			ActiveDeadlineSeconds:   new(int64(CheckTimeout.Seconds())),
			TTLSecondsAfterFinished: new(int32(600)),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					ServiceAccountName:           CheckerSA,
					AutomountServiceAccountToken: new(true),
					EnableServiceLinks:           new(false),
					NodeSelector:                 map[string]string{corev1.LabelArchStable: project.Arch, corev1.LabelOSStable: project.OS},
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   new(true),
						RunAsUser:      &uid,
						RunAsGroup:     &uid,
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name:            RoleChecker,
						Image:           image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Env: []corev1.EnvVar{
							{Name: checkerio.EnvTasks, Value: tasks},
							{Name: checkerio.EnvTargetsFile, Value: TargetsMountPath + "/" + TargetsKey},
							{Name: checkerio.EnvPackageDir, Value: PackageMountPath},
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "package", MountPath: PackageMountPath, ReadOnly: true},
							{Name: "targets", MountPath: TargetsMountPath, ReadOnly: true},
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceCPU: checkerCPU, corev1.ResourceMemory: checkerMemory},
							Limits:   corev1.ResourceList{corev1.ResourceCPU: checkerCPU, corev1.ResourceMemory: checkerMemory},
						},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: new(false),
							ReadOnlyRootFilesystem:   new(true),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "package", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: PackageConfigMap},
							Items:                items,
						}}},
						{Name: "targets", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: TargetsSecret}}},
					},
				},
			},
		},
	}
	if vm {
		pod := &job.Spec.Template.Spec
		pod.Volumes = append(pod.Volumes, corev1.Volume{Name: "ssh", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName: v1alpha1.SSHSecret,
			Items: []corev1.KeyToPath{
				{Key: v1alpha1.SSHSecretCheckerKey, Path: v1alpha1.SSHSecretCheckerKey},
				{Key: v1alpha1.SSHSecretStudentKey, Path: v1alpha1.SSHSecretStudentKey},
				{Key: v1alpha1.SSHSecretKnownHosts, Path: v1alpha1.SSHSecretKnownHosts},
			},
		}}})
		c := &pod.Containers[0]
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "ssh", MountPath: SSHMountPath, ReadOnly: true})
	}
	return job
}

func withLabels(labels map[string]string, kv ...string) map[string]string {
	out := make(map[string]string, len(labels)+len(kv)/2)
	for k, v := range labels {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func sortedKeys(data map[string]string, binaryData map[string][]byte) []string {
	keys := make([]string, 0, len(data)+len(binaryData))
	for k := range data {
		keys = append(keys, k)
	}
	for k := range binaryData {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
