# falcopb

Vendored Falco output message types.

Since Story 10.2 the collector no longer speaks gRPC to Falco: Falco 0.44.0
removed the gRPC output, and the collector now receives alerts from Falco's
`http_output` (see `../decode.go`). The `Response` message is kept as the
in-memory model the JSON body is decoded into, so `Translate`, event IDs and
`Event.Raw` are identical to what the gRPC path produced. The gRPC client stub
(`outputs_grpc.pb.go`) was deleted and `buf.gen.yaml` no longer generates it.

## Why vendored

The upstream Go client `github.com/falcosecurity/client-go` was [archived
on 2026-01-19](https://github.com/falcosecurity/client-go) with a
deprecation notice and uses old protobuf libraries
(`github.com/gogo/protobuf`, `github.com/golang/protobuf`) that no
longer match the current Go protobuf ecosystem. Story 1.6 chose to
vendor the upstream `.proto` files and generate Go bindings against
`google.golang.org/protobuf` + `google.golang.org/grpc` directly.

## Source

Files in this directory are taken verbatim from
[`falcosecurity/falco@0.43.1`](https://github.com/falcosecurity/falco/tree/0.43.1/userspace/falco)
with only the `option go_package` directive rewritten to point at this
package path. Track the upstream tag in `falcopb/buf.yaml` and bump
when the Helm subchart pin (`deploy/helm/olaitan/Chart.yaml`,
currently `falco@8.0.2`) advances to a Falco binary version where the
proto contract changes.

## Re-vendor procedure

```sh
cd internal/collector/falco/falcopb

# 1. Pull the latest upstream protos. Replace 0.43.1 with the target tag.
for f in outputs.proto schema.proto; do
  gh api "repos/falcosecurity/falco/contents/userspace/falco/$f?ref=0.43.1" \
    --jq '.content' | base64 -d > "$f"
done

# 2. Restore the local go_package directive that the upstream files do not carry.
#    (Edit each .proto so the option go_package line points at this package.)

# 3. Regenerate the Go bindings.
buf generate
```

Only the message types are generated (`buf.gen.yaml` has no gRPC plugin).
The adapter uses `Response` as the model it decodes Falco's http_output JSON
into; nothing dials a Falco gRPC service. Upstream Falco 0.44.0 deleted
`outputs.proto` together with the gRPC output (falcosecurity/falco#3798), so
re-vendor from the 0.43.1 tag, the last one that has it, or replace this
package with a hand-written struct if the model ever needs to change.
`version.proto` stays omitted: it would add duplicate `request` and
`response` types to this single Go package.

## Files

- `outputs.proto`: upstream's `falco.outputs` definitions as of 0.43.1. Only the `Request`/`Response` messages are generated; the service block is inert.
- `schema.proto`: the `falco.schema.priority` and `falco.schema.source` enums referenced by `outputs.proto`.
- `*.pb.go`: generated message bindings. Do not edit.
- `buf.{yaml,gen.yaml}`: buf config for re-generation.
