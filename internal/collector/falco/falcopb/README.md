# falcopb

Vendored Falco gRPC output protocol bindings.

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

`version.proto` is intentionally omitted: the adapter only consumes the
`outputs.service.Sub` RPC; vendoring `version.proto` would create
duplicate `request` and `response` Go types that conflict with the
outputs service in this single Go package.

## Files

- `outputs.proto`: the `falco.outputs.service` gRPC service. `Sub(stream Request) -> stream Response` plus the `Get` unary fallback.
- `schema.proto`: the `falco.schema.priority` and `falco.schema.source` enums referenced by `outputs.proto`.
- `*_grpc.pb.go` and `*.pb.go`: generated bindings. Do not edit.
- `buf.{yaml,gen.yaml}`: buf config for re-generation.
