package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/project"
)

// Config is shared by the reconcilers.
type Config struct {
	// SystemNamespace is where the operator runs. It holds the files of
	// inline challenges.
	SystemNamespace string
	// CheckerImage is the built-in checker, used unless a package sets its own.
	CheckerImage string
	// Gateway is the service account of the gateway, granted exec into the
	// machines of every instance (terminals).
	Gateway types.NamespacedName
	// GatewayExecRole and CheckerExecRole are the ClusterRoles bound in each
	// instance namespace to the gateway and the checker.
	GatewayExecRole string
	CheckerExecRole string
	// OperatorPods selects the operator's pods in SystemNamespace: the
	// network policy of instances with vm machines lets them in over SSH.
	OperatorPods map[string]string
	// Runtimes this operator can provision on this cluster (pod when empty).
	// vm needs KubeVirt, detected at startup.
	Runtimes []v1alpha1.Runtime
}

// Supports reports whether instances can use a runtime.
func (c Config) Supports(r v1alpha1.Runtime) bool {
	if len(c.Runtimes) == 0 {
		return r == v1alpha1.RuntimePod
	}
	return slices.Contains(c.Runtimes, r)
}

// Labels and annotations set by the operator.
const (
	LabelManagedBy         = "app.kubernetes.io/managed-by"
	ManagedBy              = project.Name + "-operator"
	LabelInstance          = project.LabelPrefix + "instance"
	LabelInstanceNamespace = project.LabelPrefix + "instance-namespace"
	LabelMachine           = project.LabelPrefix + "machine"
	LabelRole              = project.LabelPrefix + "role"
	LabelCheckRun          = project.LabelPrefix + "checkrun"
	RoleMachine            = "machine"
	RoleChecker            = "checker"
	// AnnotationSetupDone holds the ID of the container whose setup completed:
	// a restarted container gets a new ID and runs its setup again.
	AnnotationSetupDone = project.LabelPrefix + "setup-done"
	// Finalizer tears the instance namespace down before the instance goes.
	Finalizer = project.LabelPrefix + "cleanup"
)

// Timeouts of the lifecycle.
const (
	ProvisioningTimeout = 10 * time.Minute
	SetupTimeout        = 5 * time.Minute
	CheckTimeout        = 2 * time.Minute
	// TerminatedRetention is how long expired and failed instances stay
	// visible before the operator deletes them.
	TerminatedRetention = time.Hour
)

// Fixed names inside an instance namespace.
const (
	PackageConfigMap       = "opslab-package"
	TargetsSecret          = "opslab-checker-targets"
	TargetsKey             = "targets.json"
	CheckerSA              = "opslab-checker"
	PackageMountPath       = "/opslab/package"
	TargetsMountPath       = "/opslab/targets"
	SSHMountPath           = "/opslab/ssh"
	machineUID       int64 = 1000
)

// InstanceNamespace is the namespace holding the resources of an instance.
func InstanceNamespace(instanceName string) string {
	return dnsName("inst-", instanceName)
}

// CheckJobName is the Job running a CheckRun.
func CheckJobName(checkRunName string) string {
	return dnsName("check-", checkRunName)
}

// dnsName prefixes a name, shortening it with a hash when the result would
// exceed a DNS label (63 characters).
func dnsName(prefix, name string) string {
	const maxLen = 63
	if len(prefix)+len(name) <= maxLen {
		return prefix + name
	}
	sum := sha256.Sum256([]byte(name))
	hash := hex.EncodeToString(sum[:])[:8]
	return prefix + name[:maxLen-len(prefix)-len(hash)-1] + "-" + hash
}
