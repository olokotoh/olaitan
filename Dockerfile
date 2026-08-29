# Cross-compiling builder. BUILDPLATFORM keeps the toolchain native to the
# runner while GOARCH targets the requested platform, so a linux/arm64 image
# builds at native speed under buildx instead of under QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

# Set by buildx for every platform in the matrix.
ARG TARGETOS
ARG TARGETARCH
# Release version, stamped into `olaitan version`. Defaults to "dev" so a
# plain `docker build` (and the CI docker job) still works unchanged.
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum* ./
# Fail loudly. A go.sum checksum mismatch is exactly the signal a release
# build must not swallow.
RUN go mod download
COPY . .
# CGO stays off: the final stage is distroless/static, which has no libc.
# GOARCH takes whatever buildx supplies. BuildKit populates TARGETARCH even
# for a plain `docker build` (observed: GOARCH=amd64), and if it ever did
# not, an empty GOARCH means the Go default of the host architecture, which
# is the right answer for a local build anyway.
# -trimpath keeps runner-local absolute paths out of the binary, so the
# build is reproducible from source and the provenance attestation means
# something.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /olaitan ./cmd/olaitan

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /olaitan /olaitan

USER nonroot:nonroot
ENTRYPOINT ["/olaitan"]
