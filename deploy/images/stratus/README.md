# Stratus Red Team wrapper image (Story 11.2c)

Stratus Red Team ships release binaries, not an official container image, so
this directory builds a thin, pinned wrapper so the Kubernetes attack pack can
run `stratus detonate|revert <technique>` in-cluster with a reproducible image
(AC2/D2).

Both layers are pinned: the base images by digest in the Dockerfile, and the
Stratus release binary by a sha256 the Dockerfile verifies (from the release's
own `checksums.txt`). To bump Stratus, change `STRATUS_VERSION` and
`STRATUS_SHA256` together; the build fails if they disagree.

## Build + push (supervised step)

The image digest only exists after a build+push, so it is produced at the
supervised build step (CI or the live-gate session), which then stamps the
digest into `deploy/demo/packs/stratus-red-team/manifests/job.yaml` so the pack
pin guard (`deploy/helm/pack_pin_test.go`) sees a real `tag@sha256`. Default
target registry `ghcr.io/olokotoh/olaitan-stratus` (confirm with the operator).

    docker build -t ghcr.io/olokotoh/olaitan-stratus:v2.37.0 deploy/images/stratus
    docker push ghcr.io/olokotoh/olaitan-stratus:v2.37.0
    # then pin job.yaml to the pushed digest (docker buildx imagetools inspect)
