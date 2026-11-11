// Command operator runs the opslab controllers.
package main

import (
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/Sigeth/opslab-core-go/api/v1alpha1"
	"github.com/Sigeth/opslab-core-go/pkg/project"
	"github.com/Sigeth/opslab-operator/internal/controller"
)

func main() {
	var (
		metricsAddr string
		probeAddr   string
		leaderElect bool
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address of the metrics endpoint; 0 disables it.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address of the health and readiness probes.")
	flag.BoolVar(&leaderElect, "leader-elect", false, "Enable leader election (required with several replicas).")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("setup")

	scheme := runtime.NewScheme()
	must(clientgoscheme.AddToScheme(scheme), "registering Kubernetes types")
	must(v1alpha1.AddToScheme(scheme), "registering opslab types")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "operator." + project.APIGroup,
	})
	must(err, "creating manager")

	must((&controller.ChallengeInstanceReconciler{Client: mgr.GetClient()}).SetupWithManager(mgr), "setting up ChallengeInstance controller")

	must(mgr.AddHealthzCheck("healthz", healthz.Ping), "adding health check")
	must(mgr.AddReadyzCheck("readyz", healthz.Ping), "adding readiness check")

	log.Info("starting operator")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "manager stopped")
		os.Exit(1)
	}
}

func must(err error, what string) {
	if err != nil {
		ctrl.Log.WithName("setup").Error(err, what)
		os.Exit(1)
	}
}
