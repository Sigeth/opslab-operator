# opslab-operator

Kubernetes operator of opslab (working name). It reconciles the custom resources defined in [opslab-core-go](https://github.com/Sigeth/opslab-core-go): it installs challenges and provisions isolated environments (`ChallengeInstance`). It also runs checkers (`CheckRun`).

> Status: M0 skeleton. New `ChallengeInstance`s are admitted into the `Queued` phase; provisioning comes in M1.

## Development

Requirements: Go (version in `go.mod`), make, kubectl, and a cluster (e.g. kind) with the opslab CRDs installed.

```sh
kubectl apply --server-side -f ../core-go/crds/   # CRDs from opslab-core-go
make manifests lint test build
make run                                          # against the current kubeconfig context
make image                                        # linux/amd64 image (podman or docker)
```

RBAC is generated from the `+kubebuilder:rbac` markers into `config/rbac/role.yaml`. Run `make manifests` after changing them.

## License

[MIT](LICENSE)
