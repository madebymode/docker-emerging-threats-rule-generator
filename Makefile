.DEFAULT_GOAL := help

GO ?= go
GOFMT ?= gofmt
IMAGE ?= etr:dev
GO_FILES := $(shell git ls-files --cached --others --exclude-standard '*.go')

.PHONY: help fmt check-fmt test race vet check build docker-build docker-smoke installer-test policies

help:
	@printf '%s\n' \
	  'make fmt             Format all Go files, including native builds' \
	  'make check           Check formatting, test both builds, and run vet' \
	  'make race            Run race checks without wall-clock performance tests' \
	  'make build           Build both variants and the root helper into bin/' \
	  'make docker-smoke    Build and smoke-test the Docker image (IMAGE=etr:dev)' \
	  'make installer-test  Test native install/upgrade in disposable Docker' \
	  'make policies        Check the supported MAC policy matrix in Docker'

fmt:
	$(GOFMT) -w $(GO_FILES)

check-fmt:
	@files="$$($(GOFMT) -l $(GO_FILES))" || exit 1; \
	if [ -n "$$files" ]; then printf 'Run make fmt for:\n%s\n' "$$files"; exit 1; fi

test:
	$(GO) test ./...
	$(GO) test -tags native ./...

race:
	$(GO) test -race -short ./...
	$(GO) test -tags native -race -short ./...

vet:
	$(GO) vet ./...
	$(GO) vet -tags native ./...

check: check-fmt test vet

build:
	mkdir -p bin
	$(GO) build -o bin/etr-docker .
	$(GO) build -tags native -o bin/etr-native .
	$(GO) build -o bin/etr-apply ./cmd/etr-apply

docker-build:
	docker build --pull -t $(IMAGE) .

docker-smoke: docker-build
	sh tests/docker-smoke.sh $(IMAGE)

installer-test:
	bash tests/native-install.sh

policies:
	bash scripts/check-policies.sh dist
