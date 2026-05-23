BINARY      := bin/olaitan
MODULE      := github.com/olokotoh/olaitan
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS     := -ldflags "-X main.version=$(VERSION)"
IMAGE       := olaitan
TAG         ?= $(VERSION)
CHART_DIR        := deploy/helm/olaitan
CONFIG_SRC       := config/olaitan.yaml
AUDIT_POLICY_SRC := config/audit-policy-default.yaml
CHART_FILES      := $(CHART_DIR)/files/olaitan.yaml $(CHART_DIR)/files/audit-policy-default.yaml

.PHONY: build test lint docker-build clean helm-prepare helm-prepare-rules clean-staged-rules helm-lint helm-template helm-deps version-tag envtest-bin

# envtest-bin downloads the kube-apiserver and etcd binaries that the
# Story 1.11 posture-client integration tests (and any future
# envtest-driven tests) need. Resulting tree at bin/k8s/.
ENVTEST_K8S_VERSION ?= 1.29.x
# Pinned setup-envtest release-branch to keep `make envtest-bin`
# reproducible across CI and local checkouts. The release-branch tag
# tracks the controller-runtime minor pinned in go.mod
# (sigs.k8s.io/controller-runtime v0.24.x).
SETUP_ENVTEST_VERSION ?= release-0.24

envtest-bin: bin/setup-envtest
	bin/setup-envtest use $(ENVTEST_K8S_VERSION) --bin-dir bin/k8s >/dev/null

bin/setup-envtest:
	GOBIN=$(CURDIR)/bin go install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VERSION)

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
	# reproducibility); do not rm it during a build clean. The k8s
	# envtest binaries under bin/k8s/ are also discarded here; the
	# envtest-bin target rehydrates them.
	rm -rf bin/ $(CHART_DIR)/files $(CHART_DIR)/charts

# Prints just the image tag (no newline). Used by CI's docker smoke
# test: `docker run --rm olaitan:$(make -s version-tag) version`.
version-tag:
	@echo $(TAG)

# --- Helm chart targets -----------------------------------------------
# helm-prepare copies the canonical config files into the chart's
# files/ directory. Helm's .Files.Get is chart-relative and cannot
# traverse into parent directories, so the canonical configs must be
# duplicated at package time. The copies are build artefacts,
# gitignored; the canonical sources stay under config/. Story 1.7
# extends the set with the audit-policy default; Story 1.16 extends
# the set with the OLT rule corpus via the helm-prepare-rules target.
helm-prepare: $(CHART_FILES) helm-prepare-rules

$(CHART_DIR)/files/olaitan.yaml: $(CONFIG_SRC)
	@mkdir -p $(CHART_DIR)/files
	cp $(CONFIG_SRC) $@

$(CHART_DIR)/files/audit-policy-default.yaml: $(AUDIT_POLICY_SRC)
	@mkdir -p $(CHART_DIR)/files
	cp $(AUDIT_POLICY_SRC) $@

# helm-prepare-rules stages every OLT rule YAML under rules/<category>/
# flat into deploy/helm/olaitan/files/rules/<basename>. Helm's
# .Files.Glob uses path.Match and does not support `**`-style recursion
# (Helm 3 chart-templating docs at
# https://helm.sh/docs/chart_template_guide/accessing_files/), so the
# corpus must be flattened to a single directory before the chart can
# enumerate it via Glob. Canonical authoring location stays under
# repo-root rules/<category>/; the staged copy is a build artefact and
# is covered by the deploy/helm/olaitan/files/ wildcard in .gitignore.
RULE_SRCS := $(wildcard rules/*/*.yaml)
RULE_BASENAMES := $(notdir $(RULE_SRCS))
# Fail-fast collision check: $(eval) silently deduplicates targets, so
# two rule files sharing a basename across categories (e.g.
# rules/exec/OLT-DUP.yaml and rules/net/OLT-DUP.yaml) would otherwise
# stage only the last-evaluated source. The shell snippet emits the
# duplicate basenames; the ifneq guard converts that into a Make-time
# error before $(foreach $(eval)) runs.
RULE_DUPES := $(shell printf '%s\n' $(RULE_BASENAMES) | sort | uniq -d)
ifneq ($(strip $(RULE_DUPES)),)
$(error rule basename collision across categories: $(RULE_DUPES))
endif
RULE_STAGED := $(patsubst %,$(CHART_DIR)/files/rules/%,$(RULE_BASENAMES))

# clean-staged-rules removes the staged rules dir before staging so a
# rule deleted from rules/<category>/ does not linger in the chart and
# get packaged into the ConfigMap on the next helm-prepare. Cheap (the
# files are tiny build artefacts) and unconditional, so it doubles as
# a force-rebuild on dependency-skew edge cases.
clean-staged-rules:
	@rm -rf $(CHART_DIR)/files/rules

helm-prepare-rules: clean-staged-rules $(RULE_STAGED)

# Per-rule copy target. The foreach + eval below generates one rule per
# source file so Make tracks per-file dependencies and re-stages only
# the rules an operator just edited. The order-only `|` prerequisite on
# clean-staged-rules guarantees the rm always completes before any cp
# under `make -jN`; without it a parallel scheduler could interleave
# rm -rf and per-file cp recipes, corrupting the staged directory with
# no error.
define stage_rule
$(CHART_DIR)/files/rules/$(notdir $(1)): $(1) | clean-staged-rules
	@mkdir -p $$(@D)
	cp $$< $$@
endef
$(foreach src,$(RULE_SRCS),$(eval $(call stage_rule,$(src))))

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
