{{/*
The install notes (Story 9.3).

The body lives here rather than directly in NOTES.txt so it can be
TESTED. `helm template` does not render NOTES.txt at all, and
`helm install --dry-run=client` still needs a reachable cluster, so a
NOTES.txt written inline is unreachable from the clusterless `helm` CI
job and would quietly rot into fiction -- which is the exact failure mode
this epic exists to prevent. As a named template the helm suite can
render it into a probe manifest and assert on what it says.

NOTES.txt is then a one-line include.
*/}}
{{- define "olaitan.notes" -}}
{{- $platform := include "olaitan.platform" . -}}
{{- $source := include "olaitan.platformSource" . -}}
{{- $managed := include "olaitan.isManagedControlPlane" . -}}
{{- $cni := include "olaitan.networkPolicyProvider" . -}}
{{- $ns := .Release.Namespace -}}
{{/*
Nil-safe locals. These notes render on every helm install, so a values
file that nulls a block it does not use must not turn a cosmetic
template into an install blocker. `--set response=null` used to fail
HERE, before anything else in the chart complained.
*/}}
{{- $netpol := default (dict) (default (dict) .Values.response).networkPolicy -}}
{{- $nats := default (dict) .Values.nats -}}
Olaitan {{ .Chart.AppVersion }} is installed as "{{ .Release.Name }}" in namespace {{ $ns }}.

  Platform   : {{ if $platform }}{{ $platform }}{{ else }}unknown{{ end }} ({{ $source }})
  Kubernetes : {{ .Capabilities.KubeVersion.Version }}
{{- if eq $source "unknown" }}
               No platform marker on this cluster. That is normal on kind,
               minikube, kubeadm and AKS, none of which advertise one. Set
               `platform` if you would rather these notes state a fact than
               leave a blank.
{{- end }}

This tool decides that a workload is compromised and can cut its network. What
follows is what it concluded about THIS cluster, so you know what it can and
cannot see before you trust it.
{{- if and (ne $ns "olaitan") (not (default (dict) .Values.correlator).neverScoreReleaseNamespace) }}

! NAMESPACE
!
!   You installed into "{{ $ns }}", not "olaitan". The agent's
!   excluded_namespaces list is `kube-system` and `olaitan`, and it never
!   scores only `olaitan`, so it does NOT exclude this namespace: Olaitan
!   can score, and if enforcement is on isolate, its own aggregator and
!   collector. Either reinstall into the `olaitan` namespace, or set
!   correlator.neverScoreReleaseNamespace=true to add "{{ $ns }}" to
!   detection.correlator.never_scored_namespaces (nothing else in it is
!   scored then either).
{{- end }}

DETECTION SOURCES
{{- if (default (dict) .Values.falco).enabled }}
  [ON ] Falco syscall events -- bundled Falco subchart, posting to the
         node-local {{ include "olaitan.falcoIngest.serviceName" . }} Service on port {{ .Values.falcoIngest.port }}.
         source_healthy{source="falco"} turns 1 on Falco's first heartbeat
         (about a minute after it loads its driver). If it stays 0, check
         olaitan_sensor_falco_http_requests_total{code="401"}: a token
         mismatch between Falco and the collector shows up there.
{{- else }}
  [ ? ] Falco syscall events -- ASSUMED. falco.enabled=false, so this chart
         deployed no Falco and has established nothing about whether one is
         posting alerts to {{ include "olaitan.falcoIngest.baseURL" . }}<token>
         (token: key falco-http-token in Secret {{ include "olaitan.fullname" . }}-secrets).
         This is the primary detection source: without it the agent runs
         and sees almost nothing, quietly. Verify before you trust it (see
         VERIFY THE INSTALL below).
{{- end }}
{{- $aw := default (dict) .Values.auditWebhook }}
{{- if $aw.enabled }}
  {{- if $managed }}
  [DEGRADED] Kubernetes audit webhook -- impossible on {{ $platform }}.
         A managed control plane does not expose --audit-webhook-config-file
         on kube-apiserver, so nothing will ever reach this receiver. Set
         auditWebhook.enabled=false (values-{{ $platform }}.yaml does) so the
         gap is explicit.
  {{- else }}
  [ON ] Kubernetes audit webhook -- the receiver is up in the collector
         {{- if eq (include "olaitan.auditWebhook.tlsMode" .) "auto" }}
         (TLS made in the cluster by the certgen Job)
         {{- end }}.
         It sees nothing until kube-apiserver sends to it: hand the kubeconfig
         in Secret {{ include "olaitan.fullname" . }}-audit-webhook-kubeconfig to
         --audit-webhook-config-file (AUDIT.md, hack/audit-apiserver-patch.yaml).
         Until then it is DEGRADED: source_healthy{source="audit"} stays 0 and
         the collector logs "source DEGRADED" for it.
  {{- end }}
{{- else }}
  [OFF] Kubernetes audit webhook -- auditWebhook.enabled=false.
{{- end }}
{{- if include "olaitan.containerd.enabled" . }}
  [ON ] containerd CRI sensor -- {{ include "olaitan.containerd.socketPath" . }}
         A node with no socket there leaves it DEGRADED (the collector logs the
         path); set containerdSensor.socketPath to your runtime's socket.
{{- else if and (default (dict) .Values.containerdSensor).enabled (eq $platform "openshift") }}
  [DEGRADED] containerd CRI sensor -- OpenShift runs CRI-O, not containerd,
         so there is no socket to read and the chart mounts nothing. Container
         lifecycle still reaches the agent through Falco.
{{- else }}
  [OFF] containerd CRI sensor -- containerdSensor.enabled=false.
{{- end }}
{{- $cal := default (dict) .Values.calicoSensor }}
{{- if $cal.enabled }}
  {{- if eq (include "olaitan.calico.tlsMode" .) "none" }}
  [DEGRADED] Calico CNI flow adapter -- no Goldmane client certificate.
         Goldmane only accepts a client cert signed by the Tigera CA, and the
         chart does not read that out of calico-system on its own.
         {{- if eq $cni "Calico" }}
         Calico IS present here: issue one with cert-manager (Path A,
         calicoSensor.tls.certManagerSecretName) or supply the PEMs (Path B,
         calicoSensor.tls.caBundle/clientCert/clientKey). See CNI.md.
         {{- else }}
         It also needs Calico v3.31.5+ installed through the Tigera operator
         (which runs Goldmane); none was detected here. See CNI.md.
         {{- end }}
  {{- else }}
  [ON ] Calico CNI flow adapter -- Goldmane at {{ $cal.goldmaneAddr }}
         (needs Calico v3.31.5+ through the Tigera operator; without it the
         source stays DEGRADED and the collector says why).
  {{- end }}
{{- else }}
  [OFF] Calico CNI flow adapter -- calicoSensor.enabled=false.
{{- end }}
{{- if (default (dict) .Values.applogSidecar).enabled }}
  [ON ] Application log sidecar -- injector and admission webhook up
         {{- if eq (include "olaitan.applog.tlsMode" .) "auto" }}
         (serving cert made in the cluster by the certgen Job)
         {{- end }}.
         Injection is opt-in per pod: annotate a pod
         olaitan.io/log-sidecar: "enabled" (APPLOG.md). The source reports
         healthy once a sidecar heartbeats.
{{- else }}
  [OFF] Application log sidecar -- applogSidecar.enabled=false.
{{- end }}

ANALYSIS
{{- $an := default (dict) .Values.analyst }}
{{- $ol := default (dict) .Values.ollama }}
{{- $provider := include "olaitan.evaluation.effectiveAnalystProvider" . | lower }}
  [ON ] Rules and baselines -- the deterministic detection layer.
{{- if eq $provider "local" }}
  {{- $model := (default (dict) $an.local).model }}
  {{- $noDefaultSC := false }}
  {{- /* lookup returns an empty dict under `helm template` (no cluster: say
         nothing) and a list, possibly with no items, from a real cluster. */}}
  {{- $scs := lookup "storage.k8s.io/v1" "StorageClass" "" "" }}
  {{- if hasKey $scs "items" }}
    {{- $noDefaultSC = true }}
    {{- range $scs.items }}
      {{- $ann := default (dict) .metadata.annotations }}
      {{- if or (eq (index $ann "storageclass.kubernetes.io/is-default-class") "true") (eq (index $ann "storageclass.beta.kubernetes.io/is-default-class") "true") }}{{- $noDefaultSC = false }}{{- end }}
    {{- end }}
  {{- end }}
  {{- $olp := default (dict) $ol.persistence }}
  {{- if and $ol.enabled (not (include "olaitan.ollama.pullModels" .)) (not $olp.existingClaim) }}
  [DEGRADED] LLM analyst (L1, L2, Senior) -- {{ $model }} is not provisioned:
         nothing pulls it (ollama.pull.models is empty) and no
         ollama.persistence.existingClaim holds it. Until the model is on the
         server, every incident is scored by rules and baselines only
         (llm_unavailable). See docs/runbook.md, air-gapped section.
  {{- else if and $ol.enabled $noDefaultSC $olp.create (not $olp.storageClassName) }}
  [DEGRADED] LLM analyst (L1, L2, Senior) -- {{ $model }} on the in-cluster
         Ollama, but this cluster has no default StorageClass, so the model
         volume stays Pending and the model never loads. Set
         ollama.persistence.storageClassName (the same applies to the reports,
         NATS and Redis volumes). Until then every incident is scored by rules
         and baselines only (llm_unavailable).
  {{- else }}
  [ON ] LLM analyst (L1, L2, Senior) -- {{ $model }}
         {{- if $ol.enabled }}
         on the chart's in-cluster Ollama, no API key.
         {{- else }}
         on the Ollama at {{ default "analyst.local.endpoint" (default (dict) $an.local).endpoint }}.
         {{- end }}
         {{- if and $ol.enabled (include "olaitan.ollama.pullModels" .) }}
         The {{ include "olaitan.ollama.pullJobName" . }} Job downloads it (needs
         internet on 443 and a default StorageClass). Until it lands, incidents
         are scored by rules and baselines only and marked llm_unavailable.
         {{- end }}
         On CPU each chain role takes minutes; give Ollama a GPU node or layer
         values-llm-claude.yaml / values-llm-deepseek.yaml for a hosted model.
         {{- if hasPrefix "qwen2.5:3b" $model }}
         Licence: the 3B Qwen2.5 weights are under the Qwen Research licence,
         not Apache-2.0; for commercial use pick another model (values.yaml,
         analyst.local.model and ollama.pull.models).
         {{- end }}
  {{- end }}
{{- else if eq $provider "api" }}
  [ON ] LLM analyst (L1, L2, Senior) -- hosted model through analyst.api
         (key from secrets.llmApiKey or secrets.llmApiKeyExistingSecret; with
         no key the chain runs rules and baselines only, and says so).
{{- else }}
  [OFF] LLM analyst -- analyst.provider=none: rules and baselines only.
{{- end }}
{{- $rsp := default (dict) .Values.response }}
{{- if (default (dict) $rsp.dfir).enabled }}
  [ON ] DFIR report -- a post-mortem report per finalised incident.
{{- else }}
  [OFF] DFIR report -- response.dfir.enabled=false.
{{- end }}

RESPONSE (observe-only unless blocking is on, see ENFORCEMENT)
{{- if (default (dict) $rsp.audit).enabled }}
  [ON ] SIEM audit trail -- every state change, override and policy on the
         append-only AUDIT_* streams.
{{- else }}
  [OFF] SIEM audit trail -- response.audit.enabled=false.
{{- end }}
{{- if (default (dict) $rsp.override).enabled }}
  [ON ] Operator override -- pin a workload's state with the
         olaitan.io/state-override pod annotation.
{{- end }}
{{- if (default (dict) $rsp.settling).enabled }}
  [ON ] Settling -- an incident finalises after it has been stable for the
         settling window, which triggers the DFIR report.
{{- end }}
{{- if (default (dict) $rsp.forensics).enabled }}
  {{- if include "olaitan.forensics.storeConfigured" . }}
  [ON ] Forensic capture -- when a workload reaches PRESERVED_KILLED its
         evidence goes to the object store
         {{- if include "olaitan.blocking" . }}, then its pods are deleted.
         {{- else }}; its pods are left running (blocking is off).
         {{- end }}
  {{- else }}
  [DEGRADED] Forensic capture -- no object store configured. Set
         forensics.s3.bucket, forensics.s3.kms_key_alias,
         response.forensics.s3Endpoint and the S3 secrets (deploy/helm/README.md
         "Forensic mode"); until then the aggregator logs it DEGRADED.
  {{- end }}
{{- end }}
{{- if (default (dict) $rsp.reportArchive).enabled }}
  {{- if include "olaitan.reportArchive.storeConfigured" . }}
  [ON ] Report archive -- DFIR reports to the object store under object lock.
  {{- else }}
  [DEGRADED] Report archive -- no object store configured; DFIR reports are
         generated and announced but not archived until one is set (same
         values as forensic capture, response.reportArchive.s3Endpoint).
  {{- end }}
{{- end }}
{{- $nf := default (dict) .Values.notifications }}
{{- if or $nf.enabled (default (dict) $rsp.notifications).enabled }}
  {{- if or $nf.webhook_url .Values.secrets.notificationsWebhookUrl }}
  [ON ] Notifications -- one POST per confirmed-incident report.
  {{- else }}
  [ON ] Notifications -- idle until notifications.webhook_url (or
         secrets.notificationsWebhookUrl) is set.
  {{- end }}
{{- end }}

ENFORCEMENT
{{- if $netpol.enabled }}
  [ON ] NetworkPolicy isolation -- Olaitan WILL write policies that cut traffic
        (response.networkPolicy.enabled, the blocking switch).
  {{- $rsp0 := default (dict) .Values.response }}
  {{- if and (default (dict) $rsp0.forensics).enabled (include "olaitan.forensics.storeConfigured" .) }}
        Forensic capture also deletes a killed workload's pods once their
        evidence is uploaded.
  {{- else }}
        Forensic capture is not wired (off, or no object store), so a workload
        reaching PRESERVED_KILLED stays QUARANTINED and is not deleted.
  {{- end }}

  Read this before you rely on it. Olaitan reports a workload QUARANTINED once
  it has written the policy. Whether that workload is actually cut off is
  decided by your CNI, not by us. A cluster whose CNI does not enforce
  NetworkPolicy ACCEPTS every policy and ignores all of them: the API returns
  success and the traffic keeps flowing. Stock kind does exactly this.
  {{- if $cni }}

  {{ $cni }} is present here. That is a good sign and it is NOT proof. Prove it:
  {{- else }}

  No NetworkPolicy implementation was detected here. That may only mean it
  serves no CRD we recognise, so prove it rather than assume it:
  {{- end }}

      hack/check-netpol-enforcement.sh

  It pushes real traffic through a deny-all policy and tells you which of the
  two worlds you are in. If it reports NOT ENFORCED, set
  response.networkPolicy.enabled=false until you have a CNI that enforces --
  otherwise this tool will report containment it did not achieve.
{{- include "olaitan.notes.blockingSemantics" . }}
  {{- if not $netpol.clusterCidrs }}

  Also: response.networkPolicy.clusterCidrs is empty, so RESTRICTED allows
  the kind/Calico defaults (10.244.0.0/16, 10.96.0.0/12) on top of the RFC
  1918 ranges it always allows. Set your real pod/service CIDRs if either
  lies outside RFC 1918, or DNS goes down with a RESTRICTED workload.
  {{- end }}
{{- else }}
  [OFF] NetworkPolicy isolation -- observe-only, the default.

  Olaitan scores workloads, records and captures evidence and writes reports,
  but writes no policies, cuts no traffic and deletes no pod. Nothing it
  reports can be mistaken for containment because it is not attempting
  containment. Blocking is ONE switch:

      helm upgrade {{ .Release.Name }} <chart> -n {{ $ns }} --reuse-values \
        --set response.networkPolicy.enabled=true

  It turns on NetworkPolicy isolation AND the post-capture kill of forensic
  capture. Turning it on is a deliberate act: run
  hack/check-netpol-enforcement.sh first to confirm your CNI really enforces.
{{- include "olaitan.notes.blockingSemantics" . }}
{{- end }}

STORAGE
{{- if $nats.streamMaxBytesOverride }}
  JetStream streams are capped at {{ $nats.streamMaxBytesOverride }} bytes each, so they fit the
  default volume. For production retention, raise
  nats.config.jetstream.fileStore.pvc.size AND clear
  nats.streamMaxBytesOverride together -- the pairing is the point.
  Raising the volume alone leaves the cap in force; clearing the cap alone
  declares about 160 GiB against your volume and the first stream exhausts it.
{{- else }}
  JetStream is running at full declared retention, no per-stream cap: about
  160 GiB across the streams. nats.config.jetstream.fileStore.pvc.size must
  accommodate that or the aggregator dies on its first stream with
  err_code=10047.
{{- end }}

VERIFY THE INSTALL
  kubectl -n {{ $ns }} rollout status deploy/{{ include "olaitan.fullname" . }}-aggregator
  kubectl -n {{ $ns }} rollout status ds/{{ include "olaitan.fullname" . }}-collector
  kubectl -n {{ $ns }} get pods

  A collector in CrashLoopBackOff is almost always its Falco source. Read it
  directly rather than guessing:

  kubectl -n {{ $ns }} logs -l app.kubernetes.io/component=collector --tail=50

SEE A DETECTION
  Run something Falco flags, and watch the aggregator decide what to do:

  kubectl create namespace olaitan-demo
  kubectl -n olaitan-demo run demo --image=busybox:1.37.0 --restart=Never -- sleep 600
  kubectl -n olaitan-demo exec -it demo -- cat /etc/shadow
  kubectl -n {{ $ns }} logs -l app.kubernetes.io/component=aggregator -f

  Use a namespace the agent is not excluding. kube-system and olaitan are
  excluded by design, because it must not act on its own workloads -- a demo
  pod in one of those produces nothing and looks like a broken install.

  Clean up:  kubectl delete namespace olaitan-demo

IF SOMETHING IS OFF THAT YOU EXPECTED TO BE ON
  From a clone of https://github.com/olokotoh/olaitan:

  hack/preflight.sh          (or: make preflight)

  It probes storage, privileged-workload admission, NetworkPolicy ENFORCEMENT
  and each optional source against this cluster, and prints the exact remedy
  flag for each one. It changes nothing.
{{- end -}}


{{/*
Story 12.7 (live finding, 2026-10-19): what blocking does at each state, and
the risk window that lets a workload reach those states at all.
*/}}
{{- define "olaitan.notes.blockingSemantics" -}}
{{- $rw := include "olaitan.riskWindowSeconds" . }}

  What blocking does: RESTRICTED blocks only egress outside the private ranges
  (RFC 1918 and the cluster CIDRs stay open, so in-cluster traffic and DNS
  keep flowing, by design); QUARANTINED blocks all traffic in and out;
  PRESERVED_KILLED deletes the pods after their evidence is uploaded.
  {{- if $rw }}
  The risk window ({{ $rw }} s, aggregator.riskWindowSeconds) adds up a
  workload's signals across packages; without it no single package scores
  high enough to reach RESTRICTED. The evaluation overlays and
  values-minimal.yaml set it to 0 to reproduce earlier campaigns.
  {{- else }}
  The risk window is OFF (aggregator.riskWindowSeconds=0): each package is
  scored alone, and no single package scores high enough to reach
  RESTRICTED, so blocking would never trigger. Set it (900 is the default).
  {{- end }}
{{- end -}}
