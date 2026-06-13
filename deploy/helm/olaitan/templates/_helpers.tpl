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
{{- $valid := list "" "F" "RS" "RSL" "RSLT" -}}
{{- if not (has $cfg $valid) -}}
{{- fail (printf "evaluation.config must be one of [\"\", \"F\", \"RS\", \"RSL\", \"RSLT\"] (got %q). See deploy/helm/olaitan/values.yaml for the canonical evaluation matrix arms." $cfg) -}}
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
{{- else if or (eq $cfg "RS") (eq $cfg "RSL") (eq $cfg "RSLT") -}}true
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
{{- else if or (eq $cfg "RS") (eq $cfg "RSL") (eq $cfg "RSLT") -}}true
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
{{- else if or (eq $cfg "RSL") (eq $cfg "RSLT") -}}api
{{- else -}}{{ lower (default "none" $analyst.provider) }}
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
