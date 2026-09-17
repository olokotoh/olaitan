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
Audit webhook server address (Story 10.8, #137 B2).

kube-apiserver runs on the host network with the node's resolver, so it
cannot resolve a cluster-DNS name: the Service FQDN below is unreachable
on every self-managed cluster. auditWebhook.serverAddress overrides it
with an address the apiserver can actually dial: 127.0.0.1:<hostPort>,
with the receiver published on the node (auditWebhook.hostPort), which
keeps each apiserver talking to its own node's collector.

The address may carry its own port; without one, servicePort is used. An
IPv6 address is bracketed, as in a URL: [fd00::1] or [fd00::1]:8443.
*/}}
{{- define "olaitan.auditWebhook.server" -}}
{{- $addr := default "" .Values.auditWebhook.serverAddress | toString | trim -}}
{{- if eq $addr "" -}}
{{- printf "%s:%v" (include "olaitan.auditWebhookServiceFqdn" .) (int .Values.auditWebhook.servicePort) -}}
{{- else if regexMatch ":[0-9]+$" $addr -}}
{{- $addr -}}
{{- else -}}
{{- printf "%s:%v" $addr (int .Values.auditWebhook.servicePort) -}}
{{- end -}}
{{- end -}}

{{/*
Validation for the address the apiserver dials and the node port that
serves it (Story 10.8). Each value is checked on its own first, then
against the others, because the failure mode of a mismatch is silent:
the chart renders, the apiserver dials nothing, and the audit source
never produces an event.

Ports are matched as strings before any int conversion: Sprig's int reads
a leading zero as octal, so "0100" would become 64 and "080" would become
0 without a word.
*/}}
{{- define "olaitan.auditWebhook.validate" -}}
{{- if .Values.auditWebhook.enabled -}}
{{- $addr := default "" .Values.auditWebhook.serverAddress | toString | trim -}}
{{- $host := "" -}}
{{- $port := "" -}}
{{- if ne $addr "" -}}
{{- /* host, [ipv6], host:port or [ipv6]:port. No scheme, no path, no
       spaces: the value is interpolated into the kubeconfig server URL. */ -}}
{{- if not (regexMatch "^([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\\[[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:.]*\\])(:[0-9]{1,5})?$" $addr) -}}
{{- fail (printf "auditWebhook.serverAddress is %q: give a bare host or IP, optionally host:port, with no scheme and no path (for example 127.0.0.1:31443, or [fd00::1]:31443 for IPv6)." $addr) -}}
{{- end -}}
{{- $host = regexFind "^(\\[[^\\]]*\\]|[^:]+)" $addr -}}
{{- $port = $addr | trimPrefix $host | trimPrefix ":" -}}
{{- if and (ne $port "") (or (not (regexMatch "^[1-9][0-9]*$" $port)) (gt (int $port) 65535)) -}}
{{- fail (printf "auditWebhook.serverAddress port is %q: want 1-65535 with no leading zero." $port) -}}
{{- end -}}
{{- end -}}
{{- $hp := default 0 .Values.auditWebhook.hostPort | toString -}}
{{- if or (not (regexMatch "^(0|[1-9][0-9]*)$" $hp)) (gt (int $hp) 65535) -}}
{{- fail (printf "auditWebhook.hostPort is %q: want a number in 1-65535 with no leading zero, or 0 to leave the receiver off the node's network." $hp) -}}
{{- end -}}
{{- $hostIP := default "" .Values.auditWebhook.hostIP | toString | trim -}}
{{- if and (ne $hostIP "") (not (or (regexMatch "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$" $hostIP) (regexMatch "^[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:.]*$" $hostIP))) -}}
{{- fail (printf "auditWebhook.hostIP is %q: want an IP address with no port (default 127.0.0.1), or empty to bind every interface." $hostIP) -}}
{{- end -}}
{{- if ne $hp "0" -}}
{{- if eq $addr "" -}}
{{- fail (printf "auditWebhook.hostPort is %s but auditWebhook.serverAddress is empty, so the apiserver still dials the Service FQDN and nothing uses the node port. Set auditWebhook.serverAddress=127.0.0.1:%s." $hp $hp) -}}
{{- end -}}
{{- if not .Values.collector.runOnControlPlane -}}
{{- fail (printf "auditWebhook.hostPort is %s, so each kube-apiserver dials the collector on its own control-plane node, but collector.runOnControlPlane is false and no collector runs there. Set collector.runOnControlPlane=true." $hp) -}}
{{- end -}}
{{- end -}}
{{- if or (regexMatch "^127\\.[0-9]+\\.[0-9]+\\.[0-9]+$" $host) (eq $host "[::1]") -}}
{{- $dialled := $port | default (toString (int .Values.auditWebhook.servicePort)) -}}
{{- if eq $hp "0" -}}
{{- fail (printf "auditWebhook.serverAddress is %q, a loopback address the apiserver dials on its own node, but auditWebhook.hostPort is 0 so nothing listens there. Set auditWebhook.hostPort=%s." $addr $dialled) -}}
{{- end -}}
{{- if ne $dialled $hp -}}
{{- fail (printf "auditWebhook.serverAddress is %q, which dials port %s on the node, but auditWebhook.hostPort is %s. The two ports must match." $addr $dialled $hp) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Falco ingest (Story 10.2).

Falco POSTs each alert to the collector over HTTP (http_output). Falco
0.44.0 removed the gRPC output the collector used to dial, and the Falco
releases that run on kernel 7.x are all newer than that.

Falco's http_output.url is "${OLAITAN_FALCO_URL}${OLAITAN_FALCO_TOKEN}",
two environment variables Falco expands itself. Both come from
falco.extra.env, which the Falco subchart renders through `tpl` in the
SAME release context, so the Service FQDN and the Secret name follow the
release name and namespace with nothing for the operator to set.

The subchart cannot see this chart's values, so it names things with
olaitan.falcoIngest.releaseFullname: the olaitan.fullname rule minus
nameOverride/fullnameOverride. The guard below fails the render when those
overrides make the two disagree, with the literal values to set instead.
*/}}
{{/* NATS URL resolvable from ANY namespace (applog sidecars run in the
     workload's namespace, not this release's). endpoints.nats wins when
     set, but it must be qualified enough to resolve there: the default
     endpoints.nats is a short, namespace-local name, and a sidecar given
     that address fails DNS in every other namespace and crash-loops,
     which is the defect Story 10.10 exists to fix. Validated, not
     silently rewritten: only the operator knows their own NATS.

     Every comma-separated server is checked. Any URL scheme is stripped
     (nats, tls, ws, wss, in any case). A bracketed IPv6 host is read up to
     its closing bracket, not its first colon. localhost and loopback are
     rejected: inside a workload pod they are the pod itself, never NATS.
     Credentials (user:pass@ or a user@ token) are rejected too: the
     webhook copies this URL as a plain env var into every workload pod.
     The message never echoes the URL, so the secret does not reach logs. */}}
{{- define "olaitan.endpoints.natsFQDN" -}}
{{- if .Values.endpoints.nats -}}
{{- $url := .Values.endpoints.nats | toString -}}
{{- range $server := splitList "," $url -}}
{{- $rest := regexReplaceAll `(?i)^[a-z][a-z0-9+.-]*://` (trim $server) "" -}}
{{- if contains "@" $rest -}}
{{- fail "endpoints.nats contains credentials (user:pass@ or user@). With applogSidecar.enabled the webhook copies this URL as a plain env var into every workload pod, where anyone who can read a pod spec can read them. Remove them from the URL; NATS authentication for applog sidecars is tracked in Epic 14 (#130)." -}}
{{- end -}}
{{- $authority := $rest | splitList "/" | first -}}
{{- $host := $authority | splitList ":" | first -}}
{{- if hasPrefix "[" $authority -}}
{{- $host = regexReplaceAll `^\[([^\]]*)\].*$` $authority "${1}" -}}
{{- end -}}
{{- $h := $host | lower | trimSuffix "." -}}
{{- if or (eq $h "localhost") (hasSuffix ".localhost" $h) (regexMatch `^127\.` $h) (eq $h "::1") -}}
{{- fail (printf "endpoints.nats server %q is loopback: inside a workload pod it is the pod itself, never NATS, so every applog sidecar would crash-loop. Give the qualified NATS Service address, for example %q." $host (printf "nats://%s-nats.%s.svc:4222" $.Release.Name $.Release.Namespace)) -}}
{{- end -}}
{{- if and (not (contains "." $h)) (not (contains ":" $h)) -}}
{{- fail (printf "endpoints.nats is %q: applog sidecars run in the WORKLOAD's namespace and cannot resolve the short name %q. Give a qualified address, for example %q." $url $host (printf "nats://%s.%s.svc:4222" $host $.Release.Namespace)) -}}
{{- end -}}
{{- end -}}
{{- $url -}}
{{- else -}}
{{- printf "nats://%s.%s.svc:4222" (printf "%s-nats" .Release.Name | trunc 63 | trimSuffix "-") .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{- define "olaitan.falcoIngest.releaseFullname" -}}
{{- if contains "olaitan" .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-olaitan" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* The ingest Service name as the Falco subchart computes it: same
     63-character truncation as serviceName, from releaseFullname. */}}
{{- define "olaitan.falcoIngest.releaseServiceName" -}}
{{- printf "%s-falco-ingest" (include "olaitan.falcoIngest.releaseFullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "olaitan.falcoIngest.serviceName" -}}
{{- printf "%s-falco-ingest" (include "olaitan.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Base URL Falco posts to; the token is appended by Falco itself. */}}
{{- define "olaitan.falcoIngest.baseURL" -}}
{{- printf "http://%s.%s.svc:%v/falco/" (include "olaitan.falcoIngest.serviceName" .) .Release.Namespace .Values.falcoIngest.port -}}
{{- end -}}

{{- define "olaitan.falcoIngest.validate" -}}
{{- if .Values.falco.enabled -}}
{{- $f := default (dict) .Values.falco.falco -}}
{{- $http := default (dict) $f.http_output -}}
{{- if not $http.enabled -}}
{{- fail "falco.falco.http_output.enabled is false, but it is the only way alerts reach the collector (Falco 0.44+ has no gRPC output). Leave it enabled, or set falco.enabled=false and send alerts from your own Falco." -}}
{{- end -}}
{{- if not $f.json_output -}}
{{- fail "falco.falco.json_output is false. Falco would POST plain text and the collector would reject every alert with 415. Leave json_output enabled." -}}
{{- end -}}
{{- if ne (default "" $http.url | toString) "${OLAITAN_FALCO_URL}${OLAITAN_FALCO_TOKEN}" -}}
{{- fail (printf "falco.falco.http_output.url is %q; it must be \"${OLAITAN_FALCO_URL}${OLAITAN_FALCO_TOKEN}\" so Falco posts to this release's collector with its token (both are set through falco.extra.env)." (default "" $http.url | toString)) -}}
{{- end -}}
{{- $secret := printf "%s-secrets" (include "olaitan.fullname" .) -}}
{{- $url := "" -}}
{{- $tokenRef := dict -}}
{{- range (default (dict) .Values.falco.extra).env -}}
{{- if eq .name "OLAITAN_FALCO_URL" -}}{{- $url = default "" .value | toString -}}{{- end -}}
{{- if and (eq .name "OLAITAN_FALCO_TOKEN") .valueFrom .valueFrom.secretKeyRef -}}{{- $tokenRef = .valueFrom.secretKeyRef -}}{{- end -}}
{{- end -}}
{{- $templated := contains "olaitan.falcoIngest.releaseServiceName" $url -}}
{{- if $templated -}}
{{- if ne (include "olaitan.fullname" .) (include "olaitan.falcoIngest.releaseFullname" .) -}}
{{- fail (printf "nameOverride/fullnameOverride rename this release's resources to %q, which the Falco subchart cannot see. Set Falco's env explicitly:\n  --set-string falco.extra.env[0].value=%s\n  (and falco.extra.env[1].valueFrom.secretKeyRef.name=%s)" (include "olaitan.fullname" .) (include "olaitan.falcoIngest.baseURL" .) $secret) -}}
{{- end -}}
{{- if ne (toString .Values.falcoIngest.port) (regexFind ":[0-9]+/falco/" $url | trimPrefix ":" | trimSuffix "/falco/") -}}
{{- fail (printf "falcoIngest.port is %v but falco.extra.env OLAITAN_FALCO_URL names another port; change both together." .Values.falcoIngest.port) -}}
{{- end -}}
{{- else if ne $url (include "olaitan.falcoIngest.baseURL" .) -}}
{{- fail (printf "falco.extra.env OLAITAN_FALCO_URL is %q but this release's collector receives Falco alerts at %q." $url (include "olaitan.falcoIngest.baseURL" .)) -}}
{{- end -}}
{{- $refName := default "" $tokenRef.name | toString -}}
{{- $refOK := or (eq $refName $secret) (and (contains "olaitan.falcoIngest.releaseFullname" $refName) (eq (include "olaitan.fullname" .) (include "olaitan.falcoIngest.releaseFullname" .))) -}}
{{- if not (and $refOK (eq (default "" $tokenRef.key | toString) "falco-http-token")) -}}
{{- fail (printf "falco.extra.env does not give Falco OLAITAN_FALCO_TOKEN from Secret %s key falco-http-token. Falco would post with an unexpanded token and every alert would be rejected with 401." $secret) -}}
{{- end -}}
{{- end -}}
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

{{/*
The collector's GID, in one place. Rendered into the pod securityContext.
*/}}
{{- define "olaitan.collector.runAsGroup" -}}65532{{- end -}}
