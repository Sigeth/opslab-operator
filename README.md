# opslab-operator

Kubernetes operator of opslab (working name). It reconciles the custom resources defined in [opslab-core-go](https://github.com/Sigeth/opslab-core-go): it installs challenges and provisions isolated environments (`ChallengeInstance`). It also runs checkers (`CheckRun`).

> Status: M1. It installs inline challenges (local development), provisions `pod`-tier instances and runs checkers. Registries, signatures and the other runtimes come later.

## What it does

| Resource | Controller |
|---|---|
| `Challenge` | Validates the package (inline source: manifest in the spec, files in a ConfigMap of the operator namespace), computes its digest, and reports whether the cluster can run it (`status.runnable`). |
| `ChallengeInstance` | Creates the namespace `inst-<name>` (restricted Pod Security, quota, limits, a network policy isolating the machines, checker and gateway access), one Pod and headless Service per machine, then runs each machine's `setup` scripts. The instance is `Ready` once every machine is set up. At expiry (or on deletion) the namespace is deleted; expired and failed instances are deleted an hour later. |
| `CheckRun` | Runs the checker as a Job in the instance namespace, reads its results from the container log and writes them to the status. A missing, invalid or failed result makes the run `Error`, never a pass. |

`pod` machines run as UID/GID 1000 without privileges (restricted Pod Security Standard), so their image must work as a non-root user. Setup scripts and checks run as that user. The container gets a TTY and stdin, so images whose entrypoint is a shell stay up without a command.

## Development

Requirements: Go (version in `go.mod`), make, kubectl, and a cluster (e.g. kind) with the opslab CRDs installed.

```sh
kubectl apply --server-side -f ../core-go/crds/   # CRDs from opslab-core-go
make manifests lint test build
make run                                          # against the current kubeconfig context (needs --system-namespace)
make image                                        # linux/amd64 image (podman or docker)
```

RBAC is generated from the `+kubebuilder:rbac` markers into `config/rbac/role.yaml`. Run `make manifests` after changing them.

## License

[MIT](LICENSE)
