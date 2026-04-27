{{/*
Canonical name helpers. Modelled on upstream Bitnami/stable conventions
so an operator familiar with the Kubernetes chart ecosystem can read
this chart without surprises. Do not reinvent — keep the names stable
across releases; external tooling (kubectl label selectors, monitoring
dashboards) keys on these.
*/}}

{{- define "olaitan.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified release-scoped name. Drops the release-name prefix when
it already matches the chart name — avoids "olaitan-olaitan" for the
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
Selector labels — immutable once a Deployment/DaemonSet is created, so
they MUST NOT include the chart version or appVersion (both change on
upgrade and would break the selector match).
*/}}
{{- define "olaitan.selectorLabels" -}}
app.kubernetes.io/name: {{ include "olaitan.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Component-scoped selector labels — used on DaemonSet and Deployment to
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

{{/*
ServiceAccount name helpers. Each ring has its own SA so the RBAC grant
stays ring-scoped (Dev Notes § "RBAC: Role vs ClusterRole split"). The
SA name is deterministic from the fullname — it is not a user-tunable
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
*/}}
{{- define "olaitan.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
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
