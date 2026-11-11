// Command operator runs the opslab controllers.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/kubeexec"
	"github.com/Sigeth/opslab-core-go/pkg/project"
	"github.com/Sigeth/opslab-operator/internal/controller"
)

func main() {
	var (
		metricsAddr string
		probeAddr   string
		leaderElect bool
		gateway     string
		cfg         controller.Config
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address of the metrics endpoint; 0 disables it.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address of the health and readiness probes.")
	flag.BoolVar(&leaderElect, "leader-elect", false, "Enable leader election (required with several replicas).")
	flag.StringVar(&cfg.SystemNamespace, "system-namespace", os.Getenv("POD_NAMESPACE"), "Namespace of the operator, holding inline package files (default: $POD_NAMESPACE).")
	flag.StringVar(&cfg.CheckerImage, "checker-image", project.ImageRegistry+"/"+project.Name+"-checker:latest", "Image of the built-in checker.")
	flag.StringVar(&gateway, "gateway-service-account", project.Name+"-system/"+project.Name+"-gateway", "Service account of the gateway (namespace/name), allowed to open terminals.")
	flag.StringVar(&cfg.GatewayExecRole, "gateway-exec-role", project.Name+"-gateway-exec", "ClusterRole bound to the gateway in instance namespaces.")
	flag.StringVar(&cfg.CheckerExecRole, "checker-exec-role", project.Name+"-checker-exec", "ClusterRole bound to the checker in instance namespaces.")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("setup")

	if cfg.SystemNamespace == "" {
		must(fmt.Errorf("--system-namespace or $POD_NAMESPACE is required"), "reading flags")
	}
	ns, name, ok := strings.Cut(gateway, "/")
	if !ok {
		must(fmt.Errorf("--gateway-service-account must be namespace/name, got %q", gateway), "reading flags")
	}
	cfg.Gateway = types.NamespacedName{Namespace: ns, Name: name}

	scheme := runtime.NewScheme()
	must(clientgoscheme.AddToScheme(scheme), "registering Kubernetes types")
	must(v1alpha1.AddToScheme(scheme), "registering opslab types")

	restConfig := ctrl.GetConfigOrDie()
	mgr, err := ctrl.NewManager(restConfig, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "operator." + project.APIGroup,
		Cache:                  cacheOptions(cfg.SystemNamespace),
	})
	must(err, "creating manager")

	exec, err := kubeexec.New(restConfig)
	must(err, "creating the exec client")
	clientset, err := kubernetes.NewForConfig(restConfig)
	must(err, "creating the Kubernetes client")

	must((&controller.ChallengeReconciler{Client: mgr.GetClient(), Config: cfg}).SetupWithManager(mgr), "setting up Challenge controller")
	must((&controller.ChallengeInstanceReconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Config: cfg, Exec: exec,
	}).SetupWithManager(mgr), "setting up ChallengeInstance controller")
	must((&controller.CheckRunReconciler{
		Client: mgr.GetClient(), APIReader: mgr.GetAPIReader(), Config: cfg, Logs: podLogs{clientset},
	}).SetupWithManager(mgr), "setting up CheckRun controller")

	must(mgr.AddHealthzCheck("healthz", healthz.Ping), "adding health check")
	must(mgr.AddReadyzCheck("readyz", healthz.Ping), "adding readiness check")

	log.Info("starting operator", "systemNamespace", cfg.SystemNamespace, "checkerImage", cfg.CheckerImage)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "manager stopped")
		os.Exit(1)
	}
}

// cacheOptions keeps only opslab's objects in memory: instance pods, checker
// jobs, and the ConfigMaps of the operator namespace.
func cacheOptions(systemNamespace string) cache.Options {
	has := func(key string) labels.Selector {
		req, err := labels.NewRequirement(key, selection.Exists, nil)
		must(err, "building a label selector")
		return labels.NewSelector().Add(*req)
	}
	return cache.Options{ByObject: map[client.Object]cache.ByObject{
		&corev1.Pod{}:       {Label: has(controller.LabelInstance)},
		&batchv1.Job{}:      {Label: has(controller.LabelCheckRun)},
		&corev1.ConfigMap{}: {Namespaces: map[string]cache.Config{systemNamespace: {}}},
	}}
}

// podLogs reads container logs through the API server.
type podLogs struct{ client kubernetes.Interface }

func (p podLogs) Logs(ctx context.Context, namespace, pod, container string) (string, error) {
	limit := int64(1 << 20)
	data, err := p.client.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{Container: container, LimitBytes: &limit}).DoRaw(ctx)
	return string(data), err
}

func must(err error, what string) {
	if err != nil {
		ctrl.Log.WithName("setup").Error(err, what)
		os.Exit(1)
	}
}
