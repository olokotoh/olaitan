---
applyTo: "**/*.go"
---

# Go-specific review rules for Olaitan

These extend `.github/copilot-instructions.md` with Go-only correctness invariants. Flag any violation in the diff.

## gRPC client patterns

- **`grpc.NewClient` is lazy.** It does NOT establish a connection; the first RPC does. Health gauges must flip to healthy on the first successful `Recv`, NOT after dial or first `Send`.
- **`codes.Canceled` is not `errors.Is(context.Canceled)`.** After any `Recv` error, check `ctx.Err() != nil || status.Code(err) == codes.Canceled` and return `ctx.Err()` BEFORE marking the source unhealthy. Reference grpc-go #6862.
- **Terminal vs transient gRPC codes.**
  - Terminal (wrap in `retry.Permanent`): `codes.Unauthenticated`, `codes.PermissionDenied`, `errors.Is(err, fs.ErrPermission)`, lower-cased error message contains `"permission denied"`.
  - Transient (let outer retry handle): `codes.Unavailable`, `codes.ResourceExhausted` (a leftover collector pod still holding the gRPC subscription self-clears within `terminationGracePeriodSeconds`).
- **Half-open transport detection** is provided by gRPC keepalive (30s ping + 10s timeout via `grpc.WithKeepaliveParams`), NOT by a custom watchdog goroutine. Comments claiming a `ctxCheckEvery` watchdog are stale.
- **Bidi streams.** After the single initial `stream.Send`, call `stream.CloseSend()` so a strict server can release request-side resources.

## NATS JetStream patterns

- **At-least-once with dedup.** `PublishJS` to a JetStream-backed subject MUST pass `jetstream.WithMsgID(ev.ID)` when the event has a deterministic ID. Without it, retries on PubAck timeout duplicate-deliver inside the 2-min dedup window.
- **Per-attempt deadlines.** JetStream's default ack-wait is ~5s. Wrap each attempt in `context.WithTimeout(ctx, 2*time.Second)` so a bounded inner-retry of N attempts cannot stall past N×2s + backoff.
- **Oversize events.** Per-message terminal publish errors (lower-cased error message contains `"maximum payload"`, `"message size exceeded"`, `"max msg size"`, or `"payload too big"`) MUST be log+dropped via `retry.Permanent` without tearing the gRPC stream. Tearing the stream on an oversize message creates a tight reconnect loop because the upstream sensor re-emits the same payload immediately.
- **Subjects from constants.** Publish targets MUST come from `internal/subjects/subjects.go` constants, never string literals.

## Concurrency

- **Single-goroutine adapter rule.** Each source adapter runs in one goroutine that sequentially does `Recv → Translate → publishWithRetry`. The architecture's per-source per-node 1000 ev/s budget fits comfortably; profiling-driven parallelism is deferred. Flag PRs that introduce a worker pool or fan-out inside a single adapter.
- **Atomic snapshots.** Multi-field health state MUST be a single `atomic.Pointer[T]` to a struct, not a `(atomic.Bool, atomic.Pointer[error])` pair. The pair allows torn `(true, stale-err)` reads.
- **`-race` clean.** All tests must pass `go test -race`. Flag tests that share mutable state via package-level vars without synchronisation.

## Retry helper (`internal/retry`)

- Caller-signalled terminal errors use `retry.Permanent(err)`. `Strategy.Do` short-circuits without sleeping or further attempts.
- `MaxAttempts: 0` means unlimited. For per-publish bounded retry, use `MaxAttempts: 3` with `Min: 100ms, Max: 1s`.

## Errors

- `_, _ = fmt.Fprintf(h, ...)` for `errcheck` on infallible writes (`hash.Hash`, `bytes.Buffer`).
- `errors.Is` / `errors.As` rather than `==` / type-assertion.
