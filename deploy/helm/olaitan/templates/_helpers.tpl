{{/*
Canonical name helpers. Modelled on upstream Bitnami/stable conventions
so an operator familiar with the Kubernetes chart ecosystem can read
this chart without surprises. Do not reinvent -- keep the names stable
across releases; external tooling (kubectl label selectors, monitoring
dashboards) keys on these.
*/}}

{{- define "olaitan.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified release-scoped name. Drops the release-name prefix when
it already matches the chart name -- avoids "olaitan-olaitan" for the
canonical `helm install olaitan ./deploy/helm/olaitan` invocation.
*/}}
{{- define "olaitan.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "olaitan.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Standard label set applied to every resource. `managed-by` pins Helm
explicitly so `kubectl get` filters by managing controller keep working
even after a Helm release is uninstalled and re-adopted.
*/}}
{{- define "olaitan.labels" -}}
helm.sh/chart: {{ include "olaitan.chart" . }}
{{ include "olaitan.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels -- immutable once a Deployment/DaemonSet is created, so
they MUST NOT include the chart version or appVersion (both change on
upgrade and would break the selector match).
*/}}
{{- define "olaitan.selectorLabels" -}}
app.kubernetes.io/name: {{ include "olaitan.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Component-scoped selector labels -- used on DaemonSet and Deployment to
distinguish collector pods from aggregator pods. Value is the ring's
short name; kubelet probes and kubectl selectors both use this.
*/}}
{{- define "olaitan.collector.selectorLabels" -}}
{{ include "olaitan.selectorLabels" . }}
app.kubernetes.io/component: collector
{{- end -}}

{{- define "olaitan.aggregator.selectorLabels" -}}
{{ include "olaitan.selectorLabels" . }}
app.kubernetes.io/component: aggregator
{{- end -}}

{{- define "olaitan.ollama.selectorLabels" -}}
{{ include "olaitan.selectorLabels" . }}
app.kubernetes.io/component: ollama
{{- end -}}

{{/*
ServiceAccount name helpers. Each ring has its own SA so the RBAC grant
stays ring-scoped (Dev Notes § "RBAC: Role vs ClusterRole split"). The
SA name is deterministic from the fullname -- it is not a user-tunable
value, because rbac.yaml bindings reference it by string.
*/}}
{{- define "olaitan.collector.serviceAccountName" -}}
{{- printf "%s-collector" (include "olaitan.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "olaitan.aggregator.serviceAccountName" -}}
{{- printf "%s-aggregator" (include "olaitan.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Image reference. Splits image.tag → .Chart.AppVersion fallback out of
every template so `--set image.tag=<sha>` works consistently.

toString coerces the tag before formatting: a purely-numeric short git SHA
(e.g. 3574411) passed via `--set image.tag=<sha>` is type-inferred by Helm as
an int64, and "%s" on an int64 renders the literal "%!s(int64=3574411)" - a
malformed image ref that the kubelet rejects with InvalidImageName. toString
forces the string form so a numeric-looking tag is always a valid ref,
regardless of whether callers use --set or --set-string.
*/}}
{{- define "olaitan.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository (toString $tag) -}}
{{- end -}}

{{/*
Endpoint helpers. The default subchart Service names are
`<release>-nats` and `<release>-redis-master`; hardcoding the literal
"olaitan-" prefix in values.yaml broke any non-default release name.
These helpers fall back to the release-derived defaults when the
operator has not set an explicit override in `endpoints.<name>`.
*/}}
{{- define "olaitan.endpoints.nats" -}}
{{- if .Values.endpoints.nats -}}
{{- .Values.endpoints.nats -}}
{{- else -}}
{{- printf "nats://%s-nats:4222" .Release.Name -}}
{{- end -}}
{{- end -}}

{{- define "olaitan.endpoints.redis" -}}
{{- if .Values.endpoints.redis -}}
{{- .Values.endpoints.redis -}}
{{- else -}}
{{- printf "%s-redis-master:6379" .Release.Name -}}
{{- end -}}
{{- end -}}

{{/*
Story 1.19: Evaluation-matrix helpers. The chart exposes a single
top-level `evaluation.config` value enumerating the canonical arms (F,
RS, RSL, RSLT). When set, the chart overlays the per-arm canonical
values onto three downstream knobs (`rules.enabled`,
`baselines.enabled`, `analyst.provider`); when empty the operator's
individual knobs flow through verbatim. The four helpers below are the
single source of truth for that overlay; configmap.yaml invokes them
to compute the effective values that then feed the regex bridges.

See deploy/helm/olaitan/values.yaml `evaluation:` block for the
operator-facing semantics of each arm.
*/}}

{{/*
olaitan.evaluation.validate -- fail-fast guard invoked once at the top
of configmap.yaml. Returns the empty string on success; calls fail
with a clear message on invalid input. Pattern mirrors the
auditWebhook.caBundle and aggregator.replicas guards (loud chart-render
error rather than silent runtime trap).
*/}}
{{- define "olaitan.evaluation.validate" -}}
{{- $eval := default (dict) .Values.evaluation -}}
{{- $cfg := default "" $eval.config -}}
{{- /* Story 3.16: the LLM-bearing arms add RSLT-full and the two RSLT
       ablation modes; "RSLT" is preserved as a legacy alias for RSLT-full. */ -}}
{{- $valid := list "" "F" "RS" "RSL" "RSLT" "RSLT-full" "RSLT-L1-only" "RSLT-L1+L2" -}}
{{- if not (has $cfg $valid) -}}
{{- fail (printf "evaluation.config must be one of [\"\", \"F\", \"RS\", \"RSL\", \"RSLT\", \"RSLT-full\", \"RSLT-L1-only\", \"RSLT-L1+L2\"] (got %q). See deploy/helm/olaitan/values.yaml for the canonical evaluation matrix arms." $cfg) -}}
{{- end -}}
{{- /* Normalise provider to lowercase before the enum check so the Helm validator agrees with the Go-side validator (internal/config/config.go strings.ToLower). Without this an operator passing analyst.provider=NONE would render-fail despite the Go loader accepting it. */ -}}
{{- $analyst := default (dict) .Values.analyst -}}
{{- $ap := lower (default "none" $analyst.provider) -}}
{{- $validProviders := list "none" "api" "local" -}}
{{- if not (has $ap $validProviders) -}}
{{- fail (printf "analyst.provider must be one of [\"none\", \"api\", \"local\"] (got %q, normalised to %q). \"api\" / \"local\" are reserved for Epic 3 Story 3.x; use \"none\" for the Epic 1/2 RS evaluation arm." (default "none" $analyst.provider) $ap) -}}
{{- end -}}
{{- /* Story 3.8 (FR25): per-role providers are a concrete family or "" to
       inherit. Validate each, agreeing with the Go-side config.validate. */ -}}
{{- $validRole := list "" "claude" "openai" "ollama" "none" -}}
{{- range $field := list "l1_provider" "l2_provider" "senior_provider" -}}
{{- $rp := lower (default "" (index $analyst $field)) -}}
{{- if not (has $rp $validRole) -}}
{{- fail (printf "analyst.%s must be one of [\"\", \"claude\", \"openai\", \"ollama\", \"none\"] (got %q)" $field $rp) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
olaitan.forensics.validatePath -- Story 4.10 (BI-2) fail-fast guard for the
forensics.path facade knob. Invoked once from configmap.yaml. Returns the
empty string on success; calls fail with a clear message on an unimplemented
or unknown path.

Story 1.4 REJECTED CRIU (ADR-2026-05-02-01: containerd 1.7 lacks the
CheckpointContainer CRI RPC; the kernel vDSO blocker) and Story 4.2 shipped
ONLY the documented kubectl-logs fallback. "fallback" (and an empty value)
pass; "criu" fails with the rejection message; any other value fails with the
valid-values message. A hard template-time reject is the honest, fail-fast
posture: a silent no-op (or a warn-but-proceed) would let an operator believe
a CRIU capture is wired when only the fallback runs.
*/}}
{{- define "olaitan.forensics.validatePath" -}}
{{- $fac := default (dict) .Values.forensics -}}
{{- $path := default "fallback" $fac.path -}}
{{- if eq $path "criu" -}}
{{- fail "CRIU forensic path is not implemented (Story 1.4 rejected it per ADR-2026-05-02-01: containerd 1.7 lacks CheckpointContainer; substrate bump required). Use forensics.path=fallback." -}}
{{- else if not (or (eq $path "fallback") (eq $path "")) -}}
{{- fail (printf "forensics.path must be one of [\"fallback\", \"criu\"] (got %q). Only \"fallback\" is implemented; \"criu\" is rejected per ADR-2026-05-02-01." $path) -}}
{{- end -}}
{{- end -}}

{{/*
olaitan.evaluation.effectiveRulesEnabled -- returns the literal string
"true" or "false" for the rendered olaitan.yaml. Receiver is the regex
bridge which compares against the literal text, not a Go bool.

Mapping:
  evaluation.config="F"                       -> "false"
  evaluation.config in {RS, RSL, RSLT}        -> "true"
  evaluation.config=""  (no overlay)          -> operator-supplied
                                                 .Values.rules.enabled
*/}}
{{- define "olaitan.evaluation.effectiveRulesEnabled" -}}
{{- $eval := default (dict) .Values.evaluation -}}
{{- $cfg := default "" $eval.config -}}
{{- if eq $cfg "F" -}}false
{{- else if or (eq $cfg "RS") (eq $cfg "RSL") (hasPrefix "RSLT" $cfg) -}}true
{{- else -}}
{{- /* Bool literals false=zero-value confuse sprig's `default`, so
       check Hasley before falling through. .Values.rules is
       guaranteed by values.yaml; this nil-guard is for `--set
       rules=null` or chart-overlay edge cases. */ -}}
{{- if hasKey (default (dict) .Values.rules) "enabled" -}}{{ printf "%t" .Values.rules.enabled }}{{- else -}}true{{- end -}}
{{- end -}}
{{- end -}}

{{/*
olaitan.evaluation.effectiveBaselinesEnabled -- same shape as
effectiveRulesEnabled. The F-mode collapse and RS/RSL/RSLT raise are
symmetric with rules because the Epic 5 evaluation arms always pair
the two engines (architecture.md "rules-and-stats Olaitan").

Mapping:
  evaluation.config="F"                       -> "false"
  evaluation.config in {RS, RSL, RSLT}        -> "true"
  evaluation.config=""  (no overlay)          -> operator-supplied
                                                 .Values.baselines.enabled
*/}}
{{- define "olaitan.evaluation.effectiveBaselinesEnabled" -}}
{{- $eval := default (dict) .Values.evaluation -}}
{{- $cfg := default "" $eval.config -}}
{{- if eq $cfg "F" -}}false
{{- else if or (eq $cfg "RS") (eq $cfg "RSL") (hasPrefix "RSLT" $cfg) -}}true
{{- else -}}
{{- if hasKey (default (dict) .Values.baselines) "enabled" -}}{{ printf "%t" .Values.baselines.enabled }}{{- else -}}true{{- end -}}
{{- end -}}
{{- end -}}

{{/*
olaitan.evaluation.effectiveAnalystProvider -- returns the literal
provider string for the rendered analyst.provider line.

Mapping:
  evaluation.config in {F, RS}                -> "none"
  evaluation.config in {RSL, RSLT}            -> "api" (RSLT chain
                                                 shape is decided by
                                                 analyst.chain.enabled
                                                 in config/olaitan.yaml,
                                                 not by the provider
                                                 selector)
  evaluation.config=""  (no overlay)          -> operator-supplied
                                                 .Values.analyst.provider
*/}}
{{- define "olaitan.evaluation.effectiveAnalystProvider" -}}
{{- $eval := default (dict) .Values.evaluation -}}
{{- $cfg := default "" $eval.config -}}
{{- $analyst := default (dict) .Values.analyst -}}
{{- if or (eq $cfg "F") (eq $cfg "RS") -}}none
{{- else if or (eq $cfg "RSL") (hasPrefix "RSLT" $cfg) -}}api
{{- else -}}{{ lower (default "none" $analyst.provider) }}
{{- end -}}
{{- end -}}

{{/*
olaitan.evaluation.effectiveL2Enabled / effectiveSeniorEnabled (Story 3.16,
FR53) -- return the literal "true"/"false" for analyst.l2_enabled /
analyst.senior_enabled. The arm drives the chain ablation shape:

  RSL            -> l2 false, senior true   (Standard single-LLM; L1 acts as
                                             Senior -- effective L1-only)
  RSLT-full/RSLT -> l2 true,  senior true   (full L1 -> L2 -> Senior)
  RSLT-L1-only   -> l2 false, senior true   (L1-only ablation; SeniorEnabled
                                             precedence makes Senior off)
  RSLT-L1+L2     -> l2 true,  senior false  (L1+L2 ablation)
  F / RS / ""    -> operator-supplied .Values.analyst.{l2,senior}_enabled

The Go-side SeniorEnabledOrDefault precedence (L2 off => Senior off) means
RSL / RSLT-L1-only resolve to the L1-only chain regardless of senior; the
senior literal is set to the AC-mandated value for clarity.
*/}}
{{- define "olaitan.evaluation.effectiveL2Enabled" -}}
{{- $eval := default (dict) .Values.evaluation -}}
{{- $cfg := default "" $eval.config -}}
{{- $analyst := default (dict) .Values.analyst -}}
{{- if or (eq $cfg "RSL") (eq $cfg "RSLT-L1-only") -}}false
{{- else if or (eq $cfg "RSLT") (eq $cfg "RSLT-full") (eq $cfg "RSLT-L1+L2") -}}true
{{- else -}}
{{- if hasKey $analyst "l2_enabled" -}}{{ printf "%t" $analyst.l2_enabled }}{{- else -}}true{{- end -}}
{{- end -}}
{{- end -}}

{{- define "olaitan.evaluation.effectiveSeniorEnabled" -}}
{{- $eval := default (dict) .Values.evaluation -}}
{{- $cfg := default "" $eval.config -}}
{{- $analyst := default (dict) .Values.analyst -}}
{{- if eq $cfg "RSLT-L1+L2" -}}false
{{- else if or (eq $cfg "RSL") (eq $cfg "RSLT") (eq $cfg "RSLT-full") (eq $cfg "RSLT-L1-only") -}}true
{{- else -}}
{{- if hasKey $analyst "senior_enabled" -}}{{ printf "%t" $analyst.senior_enabled }}{{- else -}}true{{- end -}}
{{- end -}}
{{- end -}}

{{/*
olaitan.evaluation.isFArm -- returns "true" when evaluation.config=F,
empty string otherwise. AC2 requires the F arm to keep only the
Falco sensor adapter active; the configmap.yaml bridge uses this
helper to gate the four non-Falco source-adapter disables
(audit / containerd / calico / posture) so the rendered olaitan.yaml
under --set evaluation.config=F genuinely measures Falco alone for
the Epic 5 four-way comparison. Without this gate the F arm would
silently run audit/cni/containerd/posture sensors alongside Falco,
contaminating the F-vs-RS / F-vs-RSL / F-vs-RSLT deltas.
*/}}
{{- define "olaitan.evaluation.isFArm" -}}
{{- $eval := default (dict) .Values.evaluation -}}
{{- $cfg := default "" $eval.config -}}
{{- if eq $cfg "F" -}}true{{- end -}}
{{- end -}}

{{/*
Audit-webhook Service FQDN -- used by the kubeconfig Secret to tell the
kube-apiserver where to push audit batches. Story 1.7 (Kubernetes
audit-webhook receiver). Resolves to:

  <fullname>-audit-webhook.<namespace>.svc.cluster.local

The kube-apiserver runs outside this chart's namespace (kube-system),
so the FQDN must include the cluster.local suffix; truncated forms
that work for in-namespace clients break for cross-namespace dialers.
*/}}
{{- define "olaitan.auditWebhookServiceFqdn" -}}
{{- printf "%s-audit-webhook.%s.svc.cluster.local" (include "olaitan.fullname" .) .Release.Namespace -}}
{{- end -}}

{{/*
Falco socket helpers (Story 9.6).

`endpoints.falco` is either a unix:// path (the default: the collector
opens the socket the node's Falco DaemonSet created) or a tcp:// target
(an off-node Falco reached over the pod network). Everything the socket
permission fixer renders is gated on the unix:// case, because there is
no socket to chmod in the tcp:// case.
*/}}
{{- define "olaitan.falcoSocket.isUnix" -}}
{{- if hasPrefix "unix://" .Values.endpoints.falco -}}true{{- end -}}
{{- end -}}

{{/*
Absolute path of the Falco gRPC socket, taken from the same value the
collector dials so the fixer can never chmod a different file than the
one that is failing.
*/}}
{{- define "olaitan.falcoSocket.path" -}}
{{- trimPrefix "unix://" .Values.endpoints.falco -}}
{{- end -}}

{{/*
Whether the Falco socket permission fixer renders at all.

Off when the operator disabled it, and forced off for a tcp:// endpoint:
there is no socket to chmod when Falco is reached over the pod network,
so a tcp:// deployment must render neither the container nor the
read-write host mount.
*/}}
{{- define "olaitan.falcoSocket.fixerEnabled" -}}
{{- $fix := default (dict) .Values.falcoSocketPermissions -}}
{{- if and $fix.enabled (include "olaitan.falcoSocket.isUnix" .) -}}true{{- end -}}
{{- end -}}

{{/*
The Falco socket permission fixer container (Story 9.6).

Defined once and injected into one of two lists by daemonset.yaml:
`initContainers` with restartPolicy: Always (the native sidecar, ordered
before the collector's first dial), or `containers` (a plain sidecar for
clusters with the SidecarContainers gate disabled). The container body
is identical either way -- only the placement and restartPolicy differ,
which is why this is a shared template rather than two copies that could
drift.

Call with: (dict "ctx" $ "native" true|false)
*/}}
{{- define "olaitan.falcoSocket.fixerContainer" -}}
{{- $ctx := .ctx -}}
{{- $fix := $ctx.Values.falcoSocketPermissions -}}
{{- $sock := include "olaitan.falcoSocket.path" $ctx -}}
- name: falco-socket-permissions
  image: "{{ $fix.image.repository }}:{{ $fix.image.tag }}"
  imagePullPolicy: {{ $fix.image.pullPolicy }}
  {{- if .native }}
  # Native sidecar (KEP-753): an initContainers entry with
  # restartPolicy: Always starts before the collector and keeps running
  # beside it. Ordering is the reason this is the default -- the socket
  # is already group-writable when the collector makes its first dial.
  restartPolicy: Always
  {{- end }}
  command: ["/bin/sh", "-c"]
  args:
    - |
      set -u
      SOCK={{ $sock | quote }}
      MODE={{ $fix.socketMode | quote }}
      GID={{ $fix.socketGroup | quote }}
      INTERVAL={{ $fix.intervalSeconds }}
      TIMEOUT={{ $fix.waitTimeoutSeconds }}

      log() { echo "falco-socket-permissions: $*"; }

      # Say something on startup. Found on a live kind cluster: while Falco is
      # still loading its driver this container produces NO output at all, so
      # an operator debugging a collector that has not come up sees an empty
      # log and cannot tell whether the container is waiting, wedged or
      # misconfigured. One line up front costs nothing and answers that.
      log "holding $SOCK at mode $MODE group $GID, re-checking every ${INTERVAL}s"

      # Wait for Falco to create the socket. Driver load can take a
      # minute or more on first start, so a slow appearance is normal and
      # only a total absence is worth failing on.
      wait_for_socket() {
        waited=0
        [ -S "$SOCK" ] || log "waiting for $SOCK to appear (Falco may still be loading its driver; up to ${TIMEOUT}s)"
        while [ ! -S "$SOCK" ]; do
          if [ "$waited" -ge "$TIMEOUT" ]; then
            log "$SOCK did not appear within ${TIMEOUT}s."
            log "Is Falco running on this node, and is endpoints.falco the path it binds?"
            return 1
          fi
          sleep 1
          waited=$((waited + 1))
        done
        return 0
      }

      # Apply, then RE-READ from the filesystem and check the result.
      # A previous attempt at this fix set a Falco config key that does
      # not exist: the render looked right, Falco ignored it, and the
      # socket stayed 0755. Reporting success without observing the
      # outcome is how that would have shipped, so this verifies.
      apply_once() {
        before="$(stat -c '%a %u:%g' "$SOCK" 2>/dev/null)" || return 1
        chgrp "$GID" "$SOCK" 2>/dev/null
        chmod "$MODE" "$SOCK" 2>/dev/null
        after="$(stat -c '%a %u:%g' "$SOCK" 2>/dev/null)" || return 1
        [ "$before" != "$after" ] && log "$SOCK $before -> $after"
        # Group-writable is the property the collector actually needs, so
        # assert that rather than string-matching the requested mode: an
        # operator who sets 0670 or 0770 still passes.
        perms="$(stat -c '%a' "$SOCK" 2>/dev/null)"
        group_bit="$(echo "$perms" | tail -c 3 | head -c 1)"
        case "$group_bit" in
          2|3|6|7) return 0 ;;
          *) log "FAILED: $SOCK is $perms, still not group-writable."
             log "The collector (GID $GID) cannot connect to it."
             return 1 ;;
        esac
      }

      # Hold the permission for the life of the pod. A one-shot fix is
      # not enough: a Falco restart deletes and recreates the socket at
      # 0755, and an init container does not re-run when an app container
      # restarts, so the collector would be locked out until its pod was
      # recreated by hand.
      while true; do
        if [ ! -S "$SOCK" ]; then
          wait_for_socket || exit 1
        fi
        apply_once || exit 1
        sleep "$INTERVAL"
      done
  securityContext:
    # Root, because only the socket's owner may chmod it and chgrp to a
    # group the process is not in needs CAP_CHOWN. This container does
    # nothing else: no network, no untrusted input, no long-lived
    # parsing. Running the COLLECTOR as root was the rejected
    # alternative -- that would put a root process on the hot path of
    # untrusted event data, which NFR11 exists to prevent.
    runAsUser: 0
    runAsGroup: 0
    runAsNonRoot: false
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop:
        - ALL
      add:
        # CHOWN: chgrp to a group we are not a member of.
        # FOWNER: chmod when the socket is not root-owned (Falco run as a
        # non-root user under a custom securityContext).
        - CHOWN
        - FOWNER
    seccompProfile:
      type: RuntimeDefault
  resources:
    {{- toYaml $fix.resources | nindent 4 }}
  volumeMounts:
    # Read-WRITE, unlike the collector's own mount. Changing an inode's
    # mode is a write; a read-only bind mount would return EROFS.
    - name: falco-socket
      mountPath: {{ dir $sock | quote }}
{{- end -}}

{{/*
Capability detection (Story 9.3).

Until now the chart never consulted `.Capabilities` at all: it installed
the same way everywhere and told the operator nothing about what it had
concluded. These helpers exist so NOTES.txt can report what is ON, what
is OFF and WHY, in the operator's own cluster's terms.

A hard rule runs through all of them: never claim a platform we have not
actually observed. `helm template` renders offline with a stub
KubeVersion and an empty APIVersions set, and several real platforms
carry no distinguishing marker at all, so "unknown" is a normal and
honest answer. NOTES.txt says which of "declared" or "detected" it is
using, and an operator who needs certainty sets `platform` explicitly.
*/}}

{{/*
Platform identifier: one of eks, aks, gke, k3s, rke2, openshift, kind,
minikube, or "" when it could not be established.

Detection order is deliberate. An explicit `platform` value always wins,
because the operator knows more than we can infer. After that, only
signals that are genuinely diagnostic are used:

  - security.openshift.io/v1 is served only by OpenShift.
  - The API server's git version carries a vendor suffix on EKS
    (v1.29.15-eks-...), GKE (v1.29.7-gke.1...), k3s (v1.29.4+k3s1) and
    RKE2 (+rke2r1).

AKS is deliberately absent: it reports an unmodified upstream version
string and serves no distinguishing API group, so there is nothing to
detect and guessing would be worse than saying "unknown". Operators on
AKS set `platform: aks` (values-aks.yaml does).
*/}}
{{- define "olaitan.platform" -}}
{{- if .Values.platform -}}
{{- .Values.platform -}}
{{- else if .Capabilities.APIVersions.Has "security.openshift.io/v1" -}}
openshift
{{- else -}}
{{- $v := .Capabilities.KubeVersion.GitVersion | default .Capabilities.KubeVersion.Version | toString -}}
{{- if contains "-eks" $v -}}eks
{{- else if contains "-gke." $v -}}gke
{{- else if contains "+k3s" $v -}}k3s
{{- else if contains "+rke2" $v -}}rke2
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
How the platform was arrived at: "declared" (the operator set it),
"detected" (we observed it), or "unknown". NOTES.txt prints this so an
operator can tell an observation from an assumption.
*/}}
{{- define "olaitan.platformSource" -}}
{{- if .Values.platform -}}declared
{{- else if include "olaitan.platform" . -}}detected
{{- else -}}unknown
{{- end -}}
{{- end -}}

{{/*
True on a managed control plane. This is the one capability question with
a hard, non-negotiable answer: the K8s audit webhook needs
`--audit-webhook-config-file` on kube-apiserver, and EKS, AKS and GKE do
not expose kube-apiserver flags at all. No flag, no workaround, no
support ticket. The setting is not "hard" on those platforms, it is
inert, and an operator who turns it on gets silence rather than an error.
*/}}
{{- define "olaitan.isManagedControlPlane" -}}
{{- if has (include "olaitan.platform" .) (list "eks" "aks" "gke") -}}true{{- end -}}
{{- end -}}

{{/*
A NetworkPolicy implementation we can actually see, or "" when we cannot.

This is NOT a claim that policies are enforced. A cluster can serve these
CRDs and still not enforce (and, more dangerously, can accept a
NetworkPolicy object and silently ignore it -- proven on stock kind). The
only honest test is the runtime probe in hack/check-netpol-enforcement.sh,
which sends real traffic. This helper exists so NOTES.txt can say "we can
see Calico here, but you have not proven enforcement" rather than
implying either more or less than it knows.
*/}}
{{- define "olaitan.networkPolicyProvider" -}}
{{- if or (.Capabilities.APIVersions.Has "crd.projectcalico.org/v1") (.Capabilities.APIVersions.Has "operator.tigera.io/v1") (.Capabilities.APIVersions.Has "projectcalico.org/v3") -}}Calico
{{- else if .Capabilities.APIVersions.Has "cilium.io/v2" -}}Cilium
{{- end -}}
{{- end -}}
