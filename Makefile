# Contract library, tested at its newest tag by contract-latest.
CORE_GO := github.com/Sigeth/opslab-core-go
IMG ?= ghcr.io/sigeth/opslab-operator:dev
# podman or docker, whichever is installed.
CONTAINER_TOOL ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)
# Tools are built outside any go.work (-modfile is not allowed in workspace mode).
CONTROLLER_GEN := bin/controller-gen

.PHONY: all build run test lint manifests verify-generated image contract-latest

all: manifests lint test build

$(CONTROLLER_GEN): tools/go.mod
	GOWORK=off go build -modfile=tools/go.mod -o $@ sigs.k8s.io/controller-tools/cmd/controller-gen

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/operator ./cmd

## run: run against the current kubeconfig context (CRDs must be installed)
run:
	go run ./cmd

test:
	go test -race ./...

lint:
	go vet ./...
	@unformatted=$$(gofmt -l cmd internal); if [ -n "$$unformatted" ]; then echo "$$unformatted"; exit 1; fi

## manifests: RBAC role from the +kubebuilder:rbac markers
manifests: $(CONTROLLER_GEN)
	$(CONTROLLER_GEN) rbac:roleName=opslab-operator paths=./internal/... output:rbac:artifacts:config=config/rbac

verify-generated: manifests
	@changes=$$(git status --porcelain -- config); if [ -n "$$changes" ]; then echo "RBAC is out of date, run 'make manifests':"; echo "$$changes"; exit 1; fi

image:
	$(CONTAINER_TOOL) build --platform linux/amd64 -t $(IMG) .

## contract-latest: build and test against the newest opslab-core-go tag (CI),
## on a temporary copy of go.mod so the pinned version is not changed
contract-latest:
	@set -e; tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	cp go.mod go.sum "$$tmp/"; \
	export GOWORK=off GOFLAGS="-modfile=$$tmp/go.mod"; \
	go get $(CORE_GO)@latest; \
	echo "== $$(go list -m $(CORE_GO))"; \
	go build ./...; \
	go test ./...
