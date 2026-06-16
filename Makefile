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

.PHONY: build test lint olaitan-lint prereg-check analysis analysis-test docker-build clean helm-prepare helm-prepare-rules clean-staged-rules helm-prepare-prompts clean-staged-prompts helm-lint helm-template helm-deps version-tag envtest-bin e2e-local e2e-local-rslt e2e-local-forensics e2e-local-overlays eval-smoke scenarios-smoke capture-it e2e-local-down schemas helm-values-doc

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

# olaitan-lint (Story 6.5, NFR34/NFR42) mechanically enforces the two
# canonical-name conventions docs/patterns.md sections 1-2 record: a NATS
# subject must come from internal/subjects/ and a Redis key from
# internal/keys/, never from a string literal at a call site. It scans the Go
# source tree with go/ast (so comments mentioning a subject are never flagged)
# and fails non-zero on any string literal matching a canonical subject shape
# outside internal/subjects/ or a canonical key shape outside internal/keys/,
# printing file:line:col and the offending literal. This is a SEPARATE target
# (and a SEPARATE CI step) from `make lint`/golangci-lint so a canonical-name
# failure is attributable rather than buried among the staticcheck/errcheck
# output (the Story 6.3 schema-gate / 6.4 helm-doc-gate step-per-enforcement
# precedent). A genuine intentional literal is suppressed with an auditable
# `//olaitan-lint:allow <subject|key> <reason>` comment (the reason is
# mandatory). Test files are out of scope by default (NFR35 integration tests
# legitimately drive real subjects through embedded NATS).
olaitan-lint:
	go run ./cmd/olaitan-lint ./...

# prereg-check (Story 5.8) is the lightest honest structural gate for the
# pre-registered analysis plan: it asserts analysis/preregistration.md exists
# and carries the eight mandated section headings plus the confirmatory test
# registry marker (the grep idiom mirrors hack/check-prompt-changelog.sh). It
# proves STRUCTURE, not statistical correctness (a human supervisor reviews the
# numbers), and fails non-zero if any heading or the registry marker is missing.
# Wired into the always-on `go` CI job so the contract is enforced on every PR.
prereg-check:
	hack/check-preregistration.sh

# Story 5.5: the analysis pipeline targets (analysis/analyse.py, the FIRST
# Python in this Go repo). PYTHON defaults to `python3`; point it at a venv
# interpreter to use the pinned deps (analysis/requirements*.txt). `analysis`
# runs the pipeline over runs/ into analysis/output/ (it DEGRADES HONESTLY on a
# missing/partial run-set, reporting n per cell, never fabricating, BI-7).
# `analysis-test` mirrors the no-cluster CI job locally: mypy --strict + pytest.
PYTHON ?= python3
ANALYSIS_RUNS ?= runs/
ANALYSIS_OUT ?= analysis/output/

analysis:
	$(PYTHON) analysis/analyse.py --runs $(ANALYSIS_RUNS) --output $(ANALYSIS_OUT)

analysis-test:
	$(PYTHON) -m mypy --strict --config-file analysis/pyproject.toml analysis/
	$(PYTHON) -m pytest analysis/tests/

# schemas (Story 6.3, NFR40/NFR33) reflection-generates the external-
# consumer JSON-Schema files for the three plain wire/persisted carrier
# types in internal/schema (Event, EvidencePackage, WorkloadPosture)
# into docs/schemas/. It writes ONLY those three .json/.yaml pairs; the
# hand-curated model-facing schemas (l1/l2/threat_assessment/forensic_
# report/state_transition/fsm_state/audit/*) are left untouched (they
# encode constraints reflection cannot reproduce). Deterministic: a
# re-run from a clean tree is a no-op. The CI `go` job runs this then
# `git diff --exit-code docs/schemas/` so a struct change that is not
# regenerated, or a hand-edit to any committed schema, breaks the build.
schemas:
	go run ./cmd/olaitan-schemagen docs/schemas

# helm-values-doc (Story 6.4, FR47) regenerates docs/helm-values.md from
# the `# @schema ...` annotations carried in deploy/helm/olaitan/
# values.yaml. The generator parses each annotation and pairs it with the
# REAL default value beneath it in the YAML, so the documented default
# never drifts from the chart default. It also emits a "Config-file-only
# parameters" section for the FR47-named items that have no Helm value
# (excluded_namespaces, redaction patterns, per-component logging). The CI
# `go` job runs this then `git add -N docs/helm-values.md && git diff
# --exit-code docs/helm-values.md` so a values.yaml change that is not
# regenerated, or a hand-edit to the committed doc, breaks the build.
# Deterministic: a re-run from a clean tree is a no-op.
helm-values-doc:
	go run ./cmd/olaitan-helmdoc

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

# Story 4.10 (AC4, BI-6): the RSLT-full + forensics smoke. Same cluster bring-up
# as e2e-local-rslt, but it ALSO applies the in-cluster MinIO + notification-sink
# fixtures, provisions an object-lock-enabled report bucket, installs the chart
# with the four Epic-4 gates on (response.{forensics,settling,dfir,reportArchive}.
# enabled) + the forensics facade pointed at the in-cluster MinIO + the
# notifications facade pointed at the in-cluster sink, then runs the OLT_E2E_
# FORENSICS-gated forensics smoke. FR47 forensic params, FR42/NFR7 settling.
#
# HONEST GATING (PO Ratification 4): this target + tests/e2e/forensics_smoke_
# test.go are the AC4 TEST CODE. The live cluster RUN is the carry-forward
# Epic-3-retro A1 RSLT-full-kind gate before Epic 5; there is no e2e-rslt /
# e2e-forensics CI job yet, so this does NOT run in the default CI e2e job.
e2e-local-forensics: helm-prepare helm-deps docker-build
	kind get clusters | grep -q '^$(KIND_CLUSTER_NAME)$$' || \
		kind create cluster --name $(KIND_CLUSTER_NAME) --config hack/kind-config.yaml
	kind load docker-image $(IMAGE):$(TAG) --name $(KIND_CLUSTER_NAME)
	kubectl apply -f tests/e2e/fixtures/fake-llm.yaml
	kubectl apply -f tests/e2e/fixtures/minio.yaml
	kubectl apply -f tests/e2e/fixtures/notification-sink.yaml
	kubectl wait --for=condition=available --timeout=120s deploy/fake-llm deploy/minio deploy/notification-sink
	# Provision the mc alias + the object-lock-enabled, versioned report bucket
	# + the forensic-bundle bucket (the writer never creates them; the report
	# bucket MUST be object-lock-enabled + versioned, a Story 4.6 precondition).
	kubectl exec deploy/minio -- sh -c '\
		mc alias set local http://localhost:9000 olaitan-e2e olaitan-e2e-secret && \
		mc mb --ignore-existing --with-lock local/olaitan-reports && \
		mc mb --ignore-existing local/olaitan-forensics'
	helm install olaitan $(CHART_DIR) \
		--set image.repository=$(IMAGE) \
		--set-string image.tag=$(TAG) \
		--set image.pullPolicy=Never \
		--set evaluation.config=RSLT-full \
		--set analyst.l1_provider=openai \
		--set analyst.l2_provider=openai \
		--set analyst.senior_provider=openai \
		--set analyst.dfir_provider=openai \
		--set analyst.l1_model=fake --set analyst.l2_model=fake --set analyst.senior_model=fake --set analyst.dfir_model=fake \
		--set analyst.api.endpoint=http://fake-llm:8080/v1 \
		--set secrets.llmApiKey=fake-key \
		--set response.forensics.enabled=true \
		--set response.settling.enabled=true \
		--set response.dfir.enabled=true \
		--set response.reportArchive.enabled=true \
		--set response.forensics.s3Endpoint=minio:9000 \
		--set response.forensics.s3UseSsl=false \
		--set response.reportArchive.s3Endpoint=minio:9000 \
		--set response.reportArchive.s3UseSsl=false \
		--set 'forensics.s3.bucket=olaitan-reports' \
		--set 'forensics.s3.kms_key_alias=alias/olaitan-e2e' \
		--set forensics.settling_window_seconds=10 \
		--set notifications.enabled=true \
		--set notifications.webhook_url=http://notification-sink:8080/ \
		--set secrets.s3AccessKey=olaitan-e2e \
		--set secrets.s3SecretKey=olaitan-e2e-secret \
		--set baselines.warmupDuration=5s \
		--set secrets.redisPassword=ci-test \
		--set falco.enabled=false \
		--set endpoints.falco=tcp://127.0.0.1:0 \
		--set nats.streamMaxBytesOverride=1073741824 \
		--wait --timeout 5m
	KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) OLT_E2E_FORENSICS=1 go test -tags=e2e -v -count=1 -run TestKindSmoke_Forensics_FullSlice ./tests/e2e/...

# Story 6.6 (AC5): the deployment-posture overlay smoke. Installs ONE posture
# overlay (default air-gapped, the richest commitment surface: in-cluster ollama
# + empty egress) on kind and runs the OLT_E2E_OVERLAYS-gated smoke that verifies
# the operator-experience commitments (pod hardening, least-privilege RBAC,
# namespace NetworkPolicy, no external egress) against live pod / chart
# inspection. Override the overlay with OVERLAY=production|eval.
#
# HONEST GATING (Story 6.6 AC5, mirrors the e2e-local-forensics carry-forward):
# this target + tests/e2e/overlays_smoke_test.go are the AC5 TEST CODE. The live
# label-gated run (the `e2e-overlays` CI job) is the carry-forward A1-style
# cluster gate; it does NOT run in the always-on CI e2e job. The same
# commitments are covered with no cluster by the `-tags=helm` golden/knob tests.
OVERLAY ?= airgapped
e2e-local-overlays: helm-prepare helm-deps docker-build
	kind get clusters | grep -q '^$(KIND_CLUSTER_NAME)$$' || \
		kind create cluster --name $(KIND_CLUSTER_NAME) --config hack/kind-config.yaml
	kind load docker-image $(IMAGE):$(TAG) --name $(KIND_CLUSTER_NAME)
	helm install olaitan $(CHART_DIR) \
		--set image.repository=$(IMAGE) \
		--set-string image.tag=$(TAG) \
		--set image.pullPolicy=Never \
		--set secrets.redisPassword=ci-test \
		--set falco.enabled=false \
		--set endpoints.falco=tcp://127.0.0.1:0 \
		--set-string nats.streamMaxBytesOverride=536870912 \
		-f $(CHART_DIR)/values-$(OVERLAY).yaml \
		--wait --timeout 5m
	KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) OLT_E2E_OVERLAYS=1 OLT_E2E_OVERLAY=$(OVERLAY) go test -tags=e2e -v -count=1 -run TestKindSmoke_Overlays_OperatorCommitments ./tests/e2e/...

# Story 5.1 (AC5) + Story 5.3 (AC4 HALF B, BI-8): the olaitan-eval harness
# smoke. Reuses the SAME RS-arm kind bring-up as e2e-local (the chart
# installs healthy under evaluation.config=RS, Falco-off, NO LLM), builds
# the olaitan-eval binary, and runs a single S1 + RS + 1-trial
# `olaitan-eval` invocation. Story 5.3: the harness now drives the REAL RS
# helmOverlay -- the install below pre-stages the chart (release olaitan,
# namespace default, the kind image/falco overrides) and the harness then
# runs an idempotent `helm upgrade --install --reuse-values --values
# values-eval-rs.yaml --wait` + `kubectl rollout status
# deploy/olaitan-aggregator` (BI-8 option (a): make installs the kind
# prerequisites; the harness idempotently re-applies the RS arm + confirms
# Ready). Asserts the run completes, runs/<run_id>/metadata.yaml is present,
# and manifest_sha256 matches `sha256sum eval/manifest.yaml` (BI-7). The
# OLT_E2E gate is not needed: the eval-smoke test SKIPS gracefully when the
# kind cluster is absent, and it reuses the RS bring-up the default CI e2e
# job already runs, so it rides alongside the RS smoke (OA5).
#
# nats.streamMaxBytesOverride is set with --set-STRING, not bare --set
# (Story 5.3 Review Round 2, CI-caught): helm reserialises a bare-int reused
# value into scientific notation on the harness's `helm upgrade
# --reuse-values --values values-eval-rs.yaml` revision, which drifts the
# OLT_NATS_STREAM_MAXBYTES_OVERRIDE env in the aggregator/collector pod
# templates and triggers a rollout (the new aggregator hits the NATS-startup
# restart race and --wait times out). A string round-trips byte-identically,
# so the overlay re-apply is a genuine no-change upgrade (AC2 idempotency).
eval-smoke: helm-prepare helm-deps docker-build
	kind get clusters | grep -q '^$(KIND_CLUSTER_NAME)$$' || \
		kind create cluster --name $(KIND_CLUSTER_NAME) --config hack/kind-config.yaml
	kind load docker-image $(IMAGE):$(TAG) --name $(KIND_CLUSTER_NAME)
	helm install olaitan $(CHART_DIR) \
		--set image.repository=$(IMAGE) \
		--set-string image.tag=$(TAG) \
		--set image.pullPolicy=Never \
		--set evaluation.config=RS \
		--set baselines.warmupDuration=5s \
		--set secrets.redisPassword=ci-test \
		--set falco.enabled=false \
		--set endpoints.falco=tcp://127.0.0.1:0 \
		--set-string nats.streamMaxBytesOverride=1073741824 \
		--wait --timeout 5m
	go build $(LDFLAGS) -o bin/olaitan-eval ./cmd/olaitan-eval
	KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) go test -tags=e2e -v -count=1 -run TestEvalSmoke_S1_RS_OneTrial ./tests/e2e/...

# Story 5.2 (AC8, AC7): the five-attack-scenario smoke. Reuses the SAME
# RS-arm kind bring-up as e2e-local / eval-smoke (the chart installs healthy
# under evaluation.config=RS, Falco-off, baselines.warmupDuration=5s, NO
# LLM), then fires each scenario S1-S5's deterministic synthetic-event
# stimulus and asserts a rule match OR baseline deviation reaches
# EVIDENCE.packages within the scenario's target.yaml time-to-detect window,
# plus an idempotency re-run. The test SKIPS gracefully when the kind cluster
# is absent and reuses the same RS bring-up the CI e2e job runs. AC8 asserts
# the EVIDENCE-package SIGNAL, NOT the full FSM-state attainment (Story 5.4 +
# the carry-forward A1 RSLT-full-kind gate own that, BI-8).
#
# CI placement (Review Round 2, CI-caught): this smoke is NOT in the always-on
# CI e2e job. It runs in the OPT-IN `e2e-scenarios` CI job, gated by the
# `e2e-scenarios` PR label (mirroring `e2e-forensics`), because the 5-scenario
# multi-workload baseline-preseed smoke exercises the documented constrained-
# single-node-kind aggregator event-loss flakiness; the deterministic full run
# folds into the carry-forward A1 cluster gate. Each scenario now uses its OWN
# tenant-acme Deployment (scenario-<id>) so the correlator's per-workload
# rising-edge fires cleanly per scenario. Run locally any time with this target.
scenarios-smoke: helm-prepare helm-deps docker-build
	kind get clusters | grep -q '^$(KIND_CLUSTER_NAME)$$' || \
		kind create cluster --name $(KIND_CLUSTER_NAME) --config hack/kind-config.yaml
	kind load docker-image $(IMAGE):$(TAG) --name $(KIND_CLUSTER_NAME)
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
	KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) go test -tags=e2e -v -count=1 -run 'TestKindSmoke_Scenarios' ./tests/e2e/...

# capture-it runs the Story 5.4 per-run artefact-capture integration suite: an
# always-on embedded-NATS in-process test (no kind cluster) that publishes a
# deterministic S5 + RS stimulus to the real subjects, runs the rich Capturer,
# and asserts the six artefacts exist, every .jsonl parses, metadata.yaml's
# manifest_sha256 matches sha256sum eval/manifest.yaml, and the size-cap alert
# trips (AC5/AC4, BI-11). It mirrors the integration-test idiom and runs in the
# always-on integration-inproc CI job.
capture-it:
	go test -tags=integration -race -count=1 ./internal/eval/capture/...

e2e-local-down:
	kind delete cluster --name $(KIND_CLUSTER_NAME)
