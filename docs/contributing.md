# Contributing to Olaitan

This guide tells a contributor how to make a change that passes review
and CI on the first try. It is grounded in the actual build and CI
configuration (`Makefile`, `.golangci.yml`, `.github/workflows/ci.yml`,
`.github/scripts/check-traceability.sh`, `.github/copilot-instructions.md`),
so it cannot drift from what the gates actually enforce. It is written
in the Context / Decision / Consequences / Alternatives ADR shape where
a convention carries a rationale worth preserving.

## Local build, test, and lint

Three `Makefile` targets cover the day-to-day loop:

| Target | Command (Makefile) | What it does |
|---|---|---|
| `make build` | `go build $(LDFLAGS) -o $(BINARY) ./cmd/olaitan` | Compiles the single binary. |
| `make test` | `go test ./... -v -count=1` | Runs the unit suite (no cache reuse). |
| `make lint` | `golangci-lint run ./...` | Runs the linters below. |

Helm and integration helpers also exist: `make helm-lint`,
`make helm-template` (renders the chart for kubeconform), and
`make envtest-bin` (downloads the kube-apiserver and etcd binaries the
envtest integration tests need). Integration tests are tag-gated and
run with `go test -tags=integration -race` (see CI below); run them
locally with the same tag.

Before opening a PR, run `make build`, `make test`, and `make lint`
clean. `gofmt` and `goimports` must be clean too (the formatters are
part of the lint config).

## golangci-lint expectations

The lint config is `.golangci.yml` (`version: "2"`):

- **Linters enabled:** `errcheck`, `govet`, `staticcheck`, `unused`,
  `ineffassign`.
- **Formatters enabled:** `gofmt`, `goimports`, with
  `goimports.local-prefixes: github.com/olokotoh/olaitan` so the module's
  own imports group last.
- **Timeout:** `3m`.

CI installs a pinned golangci-lint and runs `golangci-lint run`. A lint
failure fails the `go` job. Keep new code `errcheck`-clean (handle or
explicitly discard every error) and `staticcheck`-clean.

## Continuous integration

`.github/workflows/ci.yml` runs these jobs on every PR:

| Job | What it enforces |
|---|---|
| `go` | `make prereg-check`, `make build`, `make test`, `golangci-lint run`. |
| `analysis` | The Python analysis pipeline: `mypy --strict` plus `pytest` over `analysis/`. |
| `prompt-changelog` | `.github/scripts/check-prompt-changelog.sh` (NFR41): any change to `internal/agent/prompts/defaults/*.txt` must be recorded with its SHA-256 hash in `docs/prompt-changelog.md`. |
| `helm` | `helm lint`, `helm template` plus `kubeconform`, and the Helm Go test suite (`go test ./deploy/helm/... -tags=helm`). |
| `docker` | `make docker-build` plus a smoke `version` run of the image. |
| `e2e` | A kind cluster running the chart under the RS arm with a smoke test (always on). |
| `integration-inproc` | `go test -tags=integration -race` against the in-process suites (embedded NATS, no external infra). |
| `integration-envtest` | `go test -tags=integration -race` against the kube-apiserver suites. |
| `traceability` | The NFR42 gate (see below). |

Heavier suites (`forensics-integration`, `report-archive-integration`,
`e2e-forensics`, `e2e-scenarios`) are MinIO-backed or label-gated.

## PR conventions

**Branch per story.** Branch off the active epic staging branch
(for example `epic-6-staging`) as `epic-N/story-N-M-<slug>`. Open the
PR with that staging branch as the base, never `main` directly.

**Commit messages.** Imperative mood, one logical change per commit.

- **No AI authorship attribution.** Commits, PR descriptions, code
  comments, and docs MUST NOT contain a `Co-Authored-By` AI trailer,
  `Generated with` lines, or any AI-agent identifier
  (`.github/copilot-instructions.md`).
- **No em-dashes** in writing the contributor owns (commit messages, PR
  bodies, `docs/`, `README.md`, code comments authored in the PR). Use
  ` - ` or `, ` instead. Existing em-dashes outside the PR's scope are
  not in scope.
- **British English** in writing the contributor owns (behaviour,
  organisation, serialise, recognise). Identifiers and standard-library
  names stay as they are.

**Review gate.** Every PR runs two rounds of code review plus a pass to
pick up automated (Copilot) review comments before the merge gate. The
first round hunts for bugs and acceptance gaps; the second round is a
regression and completeness pass over the first round's patches.

## The `traceability_updated` field (NFR42)

Every PR body must carry a `traceability_updated:` field, and CI gates
on it (`.github/scripts/check-traceability.sh`, run by the
`traceability` job; self-tested by `.github/scripts/check-traceability.bats`).
The rule is matrix-or-rationale:

- `traceability_updated: yes` requires that `docs/traceability.md`
  appears in the PR's changed-file list. Add (or amend) a row whose
  `claim_id` is unique, sort the table by `claim_id`, and record the
  PR number, merge SHA, and the FRs/NFRs in the Provenance annex.
- `traceability_updated: no` requires a non-empty
  `### Traceability rationale` section in the PR body (after stripping
  HTML comments and whitespace), for example a docs-only change that
  touches no FR/NFR.

Any other value (or a missing field) fails the build.

> **Gotcha (do not lose a day to this).** The gate matches the line with
> the anchored regex `^\s*traceability_updated:`. Write it as a BARE
> line. Do NOT wrap it in backticks or a code span: a backtick prefix
> defeats the anchor and fails the gate even though the value is `yes`.

The matrix row format is six columns
(`claim_id | ch3_section | code_package | test_files | test_ids | eval_run_ids`);
see the column schema and the slug grammar at the top of
`docs/traceability.md`. A `claim_id` is a stable slug of the form
`c<chapter>.<section>[.<sub>]-<short-slug>`. Use `n/a` (with a recorded
rationale in Provenance) for intentionally test-free rows such as
docs-only claims.

## Test conventions

**Real dependency boundaries (NFR35).** Integration tests must drive the
system through a real boundary, not a mock. JetStream tests use an
embedded `github.com/nats-io/nats-server/v2`; in-process gRPC tests use
`google.golang.org/grpc/test/bufconn`. An acceptance criterion is
satisfied by observing real behaviour through the boundary, never by
inspecting a mock-internal slice.

**Assertions fail the test.** Use `t.Errorf` / `t.Fatalf` for any
acceptance-relevant assertion. `t.Logf` does not fail a test, so an
acceptance check written as `t.Logf` is a silent pass and is a review
blocker.

**Table-driven.** Prefer table-driven tests with one `t.Run(name, ...)`
per case.

**Fixtures and golden files.** Test fixtures live in a `testdata/`
directory next to the test (for example
`internal/decision/rules/testdata/`, `internal/response/audit/testdata/`,
`internal/collector/cni/testdata/`). Golden files (`*.golden.yaml`,
under `deploy/helm/testdata/golden/`) pin rendered output so drift fails
the build; regenerate them with `HELM_GOLDEN_UPDATE=1` and review the
diff before committing. Committed JSON/YAML schema exemplars live under
`docs/schemas/` and are validated against the schema in the relevant
test.

## Forbidden patterns

These are review blockers, called out so a contributor catches them
before the reviewer does.

- **String-literal NATS subjects.** Never hard-code a subject string at a
  call site. Use the constants and validating builders in
  `internal/subjects/` (see `docs/patterns.md` section 1). A literal
  subject is invisible to a rename and skips the reserved-character
  guard. This is a convention enforced in review (and by the
  `internal/subjects` conformance tests), not yet a custom linter; treat
  it as binding.
- **Mock-only ring crossings (NFR35).** Do not assert an acceptance
  criterion by reaching into a mock's internal state. Drive the real
  boundary (embedded NATS, bufconn) and assert on the observed result.
- **AI authorship attribution.** No `Co-Authored-By` AI trailer or any
  AI-agent identifier anywhere a human owns the text (see PR conventions
  above).
- **Em-dashes** in writing the contributor owns (see PR conventions).

## Where to record a decision

A change that makes a load-bearing architectural choice records it as an
ADR under `docs/`: schema-version changes in `docs/schema-versioning.md`,
a deferred or rejected design in `docs/deferred-decisions.md`, a reusable
code pattern in `docs/patterns.md`. The `docs/README.md` index links all
of them.
