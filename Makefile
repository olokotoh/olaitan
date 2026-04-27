BINARY      := bin/olaitan
MODULE      := github.com/olokotoh/olaitan
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS     := -ldflags "-X main.version=$(VERSION)"
IMAGE       := olaitan
TAG         ?= $(VERSION)
CHART_DIR   := deploy/helm/olaitan
CONFIG_SRC  := config/olaitan.yaml
CHART_FILES := $(CHART_DIR)/files/olaitan.yaml

.PHONY: build test lint docker-build clean helm-prepare helm-lint helm-template helm-deps version-tag

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/olaitan

test:
	go test ./... -v -count=1

lint:
	golangci-lint run ./...

docker-build:
	docker build -t $(IMAGE):$(TAG) .

clean:
	# Chart.lock is committed to the repo (it pins subchart digests for
	# reproducibility); do not rm it during a build clean.
	rm -rf bin/ $(CHART_DIR)/files $(CHART_DIR)/charts

# Prints just the image tag (no newline). Used by CI's docker smoke
# test: `docker run --rm olaitan:$(make -s version-tag) version`.
version-tag:
	@echo $(TAG)

# --- Helm chart targets -----------------------------------------------
# helm-prepare copies config/olaitan.yaml into the chart's files/
# directory. Helm's .Files.Get is chart-relative and cannot traverse
# into parent directories, so the canonical config must be duplicated
# at package time. The copy is a build artefact, gitignored; the
# canonical source stays in config/olaitan.yaml.
helm-prepare: $(CHART_FILES)

$(CHART_FILES): $(CONFIG_SRC)
	@mkdir -p $(CHART_DIR)/files
	cp $(CONFIG_SRC) $(CHART_FILES)

# helm-deps runs `helm dependency update` so the subchart tarballs
# (Falco, NATS, Redis) land in deploy/helm/olaitan/charts/. Required
# before helm-lint or helm-template from a fresh checkout.
helm-deps: helm-prepare
	helm dependency update $(CHART_DIR)

helm-lint: helm-prepare
	helm lint $(CHART_DIR)

# helm-template renders the chart to stdout; pipe into kubeconform for
# schema validation (see deploy/helm/README.md).
helm-template: helm-prepare
	helm template olaitan $(CHART_DIR)
