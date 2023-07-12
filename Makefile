GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null)
GIT_TAG := $(shell git describe --tags 2>/dev/null)
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w -X github.com/4data-ch/openldap_exporter.commit=${GIT_COMMIT}
LDFLAGS := ${LDFLAGS} -X github.com/4data-ch/openldap_exporter.tag=${GIT_TAG}
OUTFILE ?= openldap_exporter

.PHONY: precommit
precommit: clean format lint compile

.PHONY: commit
commit: clean cross-compile
	ls -lha target/

.PHONY: clean
clean:
	rm -rf target

target:
	mkdir target

.PHONY: format
format:
	@echo 'goimports ./...'
	@goimports -w -local github.com/4data-ch/openldap_exporter $(shell find . -type f -name '*.go' | grep -v '/vendor/')

.PHONY: lint
lint:
	golangci-lint run

.PHONY: compile
compile: target
	go build -ldflags "${LDFLAGS}" -o target/${OUTFILE} ./cmd/openldap_exporter/...
	gzip -c < target/${OUTFILE} > target/${OUTFILE}.gz

.PHONY: cross-compile
cross-compile:
	OUTFILE=openldap_exporter-linux-amd64 GOOS=linux GOARCH=amd64 $(MAKE) compile
	OUTFILE=openldap_exporter-linux-nocgo CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(MAKE) compile
	OUTFILE=openldap_exporter-osx-amd64 GOOS=darwin GOARCH=amd64 $(MAKE) compile
	OUTFILE=openldap_exporter-osx-arm64 GOOS=darwin GOARCH=arm64 $(MAKE) compile
	(cd target && find . -name '*.gz' -exec sha256sum {} \;) > target/verify.sha256

.PHONY: vendor
vendor:
	go mod tidy -compat=1.20
	go mod vendor


.PHONY: build-container
container:
	docker build --build-arg GIT_COMMIT=${GIT_COMMIT} --build-arg GIT_TAG=${GIT_TAG} --build-arg BUILD_DATE=${BUILD_DATE} --build-arg VCS_REF=${VCS_REF} Dockerfile 4dataag/openldap-exporter:${GIT_TAG}
