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

.PHONY: build test lint docker-build clean helm-prepare helm-prepare-rules clean-staged-rules helm-prepare-prompts clean-staged-prompts helm-lint helm-template helm-deps version-tag envtest-bin e2e-local e2e-local-down

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
helm-prepare: $(CHART_FILES) helm-prepare-rules helm-prepare-prompts

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

# helm-prepare-prompts stages the per-role default prompts (Story 3.13)
# from the canonical internal/agent/prompts/defaults/<role>.txt into
# deploy/helm/olaitan/files/prompts/<role>.txt so the prompts ConfigMap
# template can enumerate them via .Files.Glob (which cannot traverse into
# parent directories). The staged copies are build artefacts covered by
# the deploy/helm/olaitan/files/ wildcard in .gitignore; the canonical
# source is the same defaults/ tree the controller binary embeds, so the
# mounted ConfigMap and the embedded fallback are byte-identical at build.
PROMPT_SRCS    := $(wildcard internal/agent/prompts/defaults/*.txt)
PROMPT_STAGED  := $(patsubst internal/agent/prompts/defaults/%,$(CHART_DIR)/files/prompts/%,$(PROMPT_SRCS))

clean-staged-prompts:
	@rm -rf $(CHART_DIR)/files/prompts

helm-prepare-prompts: clean-staged-prompts $(PROMPT_STAGED)

define stage_prompt
$(CHART_DIR)/files/prompts/$(notdir $(1)): $(1) | clean-staged-prompts
	@mkdir -p $$(@D)
	cp $$< $$@
endef
$(foreach src,$(PROMPT_SRCS),$(eval $(call stage_prompt,$(src))))

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

# --- Story 1.19: kind-based RS smoke test ----------------------------
# `make e2e-local` spins up a single-node kind cluster, builds the
# Olaitan image, loads it into the cluster, installs the chart under
# the RS evaluation arm with Falco disabled (eBPF unavailable inside
# kind nodes), and runs the e2e smoke test. `make e2e-local-down`
# tears the cluster back down. KIND_CLUSTER_NAME is overridable so a
# developer can run two smoke clusters side-by-side without collision.

KIND_CLUSTER_NAME ?= olaitan-e2e

e2e-local: helm-prepare helm-deps docker-build
	# Skip cluster create when one with this name already exists so a
	# repeated `make e2e-local` reuses the previous cluster instead of
	# erroring on "node(s) already exist for a cluster with the name".
	kind get clusters | grep -q '^$(KIND_CLUSTER_NAME)$$' || \
		kind create cluster --name $(KIND_CLUSTER_NAME) --config hack/kind-config.yaml
	kind load docker-image $(IMAGE):$(TAG) --name $(KIND_CLUSTER_NAME)
	# Story 1.19 D6: instead of lying to JetStream about disk capacity
	# via fileStore.maxSize=200GB, cap each stream's MaxBytes at 1 GiB
	# via the OLT_NATS_STREAM_MAXBYTES_OVERRIDE env var (wired through
	# nats.streamMaxBytesOverride). Sum of caps (3 streams) is 3 GiB,
	# well under the kind node's PVC backing.
	helm install olaitan $(CHART_DIR) \
		--set image.repository=$(IMAGE) \
		--set-string image.tag=$(TAG) \
		--set image.pullPolicy=Never \
		--set evaluation.config=RS \
		--set baselines.warmupDuration=5s \
		--set secrets.redisPassword=ci-test \
		--set falco.enabled=false \
		--set endpoints.falco=tcp://127.0.0.1:0 \
		--set nats.streamMaxBytesOverride=1073741824 \
		--wait --timeout 5m
	KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) go test -tags=e2e -v -count=1 ./tests/e2e/...

# Story 3.16 (AC7): the RSLT-full smoke. Same cluster bring-up as e2e-local,
# but it first applies the in-cluster fake-LLM fixture (the olaitan binary's
# `fake-llm` OpenAI-compatible canned-verdict server), then installs the chart
# under evaluation.config=RSLT-full with every analyst role routed to the
# fake-LLM via the openai_compat provider (analyst.api.endpoint -> the fake-LLM
# Service), so the deployed full L1->L2->Senior chain runs against a real
# provider transport with no external egress. The OLT_E2E_RSLT gate selects
# the RSLT assertion test (skips the RS smoke). FR48 air-gapped: no paid LLM.
e2e-local-rslt: helm-prepare helm-deps docker-build
	kind get clusters | grep -q '^$(KIND_CLUSTER_NAME)$$' || \
		kind create cluster --name $(KIND_CLUSTER_NAME) --config hack/kind-config.yaml
	kind load docker-image $(IMAGE):$(TAG) --name $(KIND_CLUSTER_NAME)
	kubectl apply -f tests/e2e/fixtures/fake-llm.yaml
	kubectl wait --for=condition=available --timeout=120s deploy/fake-llm
	helm install olaitan $(CHART_DIR) \
		--set image.repository=$(IMAGE) \
		--set-string image.tag=$(TAG) \
		--set image.pullPolicy=Never \
		--set evaluation.config=RSLT-full \
		--set analyst.l1_provider=openai \
		--set analyst.l2_provider=openai \
		--set analyst.senior_provider=openai \
		--set analyst.l1_model=fake --set analyst.l2_model=fake --set analyst.senior_model=fake \
		--set analyst.api.endpoint=http://fake-llm:8080/v1 \
		--set secrets.llmApiKey=fake-key \
		--set baselines.warmupDuration=5s \
		--set secrets.redisPassword=ci-test \
		--set falco.enabled=false \
		--set endpoints.falco=tcp://127.0.0.1:0 \
		--set nats.streamMaxBytesOverride=1073741824 \
		--wait --timeout 5m
	KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) OLT_E2E_RSLT=1 go test -tags=e2e -v -count=1 ./tests/e2e/...

e2e-local-down:
	kind delete cluster --name $(KIND_CLUSTER_NAME)
