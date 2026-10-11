# Story 11.2c (D2): a thin wrapper image for DataDog Stratus Red Team, which
# ships NO official container image (only release binaries). Both layers are
# pinned: the base images by digest, and the Stratus release binary by a
# sha256 this Dockerfile VERIFIES before it lands in the image - so this is a
# real pin, not a pinned envelope around an unpinned download (Winston).
#
# The release binary + its checksum are from
# https://github.com/DataDog/stratus-red-team/releases/tag/v2.37.0
# (checksums.txt, stratus-red-team_Linux_x86_64.tar.gz), verified 2026-10-11.
#
# Build + push happens at the supervised build step (CI or the live-gate
# session), which stamps the resulting image digest into the Stratus Job
# manifest so the pack pin guard sees a real tag@sha256. Target registry:
# ghcr.io/olokotoh/olaitan-stratus (to confirm with the operator).

ARG STRATUS_VERSION=v2.37.0
ARG STRATUS_SHA256=5cd738da2c586d036f5e0b478b8334e6acb82c07a483e34ffd52889bf452436e

# --- fetch + verify + extract -------------------------------------------------
FROM alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507 AS fetch
ARG STRATUS_VERSION
ARG STRATUS_SHA256
RUN apk add --no-cache ca-certificates
WORKDIR /out
# wget (busybox) fetches the exact release asset; sha256sum -c fails the build
# if the download does not match the checked-in checksum.
RUN set -eux; \
    wget -q --tries=3 --timeout=30 -O stratus.tar.gz \
      "https://github.com/DataDog/stratus-red-team/releases/download/${STRATUS_VERSION}/stratus-red-team_Linux_x86_64.tar.gz"; \
    echo "${STRATUS_SHA256}  stratus.tar.gz" | sha256sum -c -; \
    tar -xzf stratus.tar.gz stratus; \
    chmod 0555 stratus

# --- minimal runtime ----------------------------------------------------------
# distroless/static: the Stratus release is a statically linked Go binary that
# talks to the API server via client-go, so no shell or kubectl is needed in
# this image. The Job's init container synthesizes the in-cluster kubeconfig
# (D3) into a shared volume and sets KUBECONFIG for this container.
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=fetch /out/stratus /usr/local/bin/stratus
COPY --from=fetch /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/stratus"]
