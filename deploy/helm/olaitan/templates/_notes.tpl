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
{{- $unixFalco := include "olaitan.falcoSocket.isUnix" . -}}
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
{{- if ne $ns "olaitan" }}

! NAMESPACE
!
!   You installed into "{{ $ns }}", not "olaitan". The agent's
!   excluded_namespaces list is `kube-system` and `olaitan`, so it does NOT
!   exclude this namespace: Olaitan can score, and if enforcement is on
!   isolate, its own aggregator and collector. Either reinstall into the
!   `olaitan` namespace, or add "{{ $ns }}" to excluded_namespaces.
{{- end }}

DETECTION SOURCES
{{- if (default (dict) .Values.falco).enabled }}
  [ON ] Falco syscall events -- bundled Falco subchart, via {{ .Values.endpoints.falco }}
{{- else }}
  [ ? ] Falco syscall events -- ASSUMED, via {{ .Values.endpoints.falco }}
         falco.enabled=false, so this chart deployed no Falco and has
         established nothing about whether one is listening there. This is
         the primary detection source: if nothing is at that address the
         agent runs and sees almost nothing, quietly. Verify before you
         trust it (see VERIFY THE INSTALL below).
{{- end }}
{{- if eq (include "olaitan.falcoSocket.fixerEnabled" .) "true" }}
         Falco creates that socket 0755 root:root and the collector runs as
         UID 65532, so it could not connect to it. The
         falco-socket-permissions {{ if .Values.falcoSocketPermissions.useNativeSidecar }}sidecar{{ else }}container{{ end }} holds it at {{ .Values.falcoSocketPermissions.socketMode }} group
         {{ .Values.falcoSocketPermissions.socketGroup }}. If the collector ever logs "connect: permission denied",
         look there first: it is the difference between events and silence.
{{- else if $unixFalco }}
         falcoSocketPermissions is OFF. If the collector logs
         "connect: permission denied", that is why: Falco's socket is
         0755 root:root and the collector (UID 65532) cannot attach.
{{- end }}
{{- if (default (dict) .Values.auditWebhook).enabled }}
  [ON ] Kubernetes audit webhook
  {{- if $managed }}
         WARNING: {{ $platform }} is a managed control plane. It does not expose
         --audit-webhook-config-file on kube-apiserver, so nothing will ever
         reach this receiver. It is enabled and inert, and there is no
         workaround. Set auditWebhook.enabled=false so the gap is visible.
  {{- end }}
{{- else }}
  [OFF] Kubernetes audit webhook
  {{- if $managed }}
         Impossible on {{ $platform }}, not merely off: a managed control plane does
         not expose --audit-webhook-config-file. Nothing you can set here
         turns this on.
  {{- else if $platform }}
         Off by default. On {{ $platform }} you control the API server, so it IS
         available: auditWebhook.enabled=true plus hack/audit-apiserver-patch.yaml.
  {{- else }}
         Off by default, and whether you CAN turn it on depends on a
         platform this chart could not identify. It needs
         --audit-webhook-config-file on kube-apiserver, which self-managed
         clusters expose and EKS, AKS and GKE do not. AKS in particular is
         undetectable from inside the cluster, so an unidentified platform
         may well be one where this is impossible. Set `platform` and these
         notes will tell you which.
  {{- end }}
{{- end }}
{{- if (default (dict) .Values.containerdSensor).enabled }}
  [ON ] containerd CRI sensor -- {{ .Values.containerdSensor.socketPath }}
{{- else }}
  [OFF] containerd CRI sensor
  {{- if eq $platform "k3s" }}
         Off by default. On k3s the socket is at
         /run/k3s/containerd/containerd.sock, not the chart default, so
         enabling it also needs containerdSensor.socketPath set.
  {{- else }}
         Off by default; needs a host socket path matching your runtime.
  {{- end }}
{{- end }}
{{- if (default (dict) .Values.calicoSensor).enabled }}
  [ON ] Calico CNI flow adapter
{{- else }}
  [OFF] Calico CNI flow adapter
  {{- if eq $cni "Calico" }}
         Calico IS present here, so this source is available to you:
         calicoSensor.enabled=true (needs Goldmane and its mTLS material).
  {{- else }}
         Off by default; requires Calico installed via the Tigera operator.
  {{- end }}
{{- end }}
{{- if (default (dict) .Values.applogSidecar).enabled }}
  [ON ] Application log sidecar -- injected by the admission webhook
{{- else }}
  [OFF] Application log sidecar
         Off by default; it injects a sidecar into your workloads through an
         admission webhook, which is a bigger consent decision than the
         other sources and is left to you.
{{- end }}

ENFORCEMENT
{{- if $netpol.enabled }}
  [ON ] NetworkPolicy isolation -- Olaitan WILL write policies that cut traffic.

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
  {{- if not $netpol.clusterCidrs }}

  Also: response.networkPolicy.clusterCidrs is EMPTY. Set it to your real
  pod/service CIDRs before relying on this. Left empty, egress blocking under
  RESTRICTED takes DNS down with the workload.
  {{- end }}
{{- else }}
  [OFF] NetworkPolicy isolation -- observe-only, the default.

  Olaitan scores workloads and records evidence but writes no policies and
  cuts no traffic. Nothing it reports can be mistaken for containment because
  it is not attempting containment. Turning this on is a deliberate act: run
  hack/check-netpol-enforcement.sh first to confirm your CNI really enforces,
  and set response.networkPolicy.clusterCidrs to your cluster's real CIDRs.
{{- end }}

STORAGE
{{- if $nats.streamMaxBytesOverride }}
  JetStream streams are capped at {{ $nats.streamMaxBytesOverride }} bytes each, so they fit the
  default volume. For production retention, raise nats.persistence.size AND
  clear nats.streamMaxBytesOverride together -- the pairing is the point.
  Raising the volume alone leaves the cap in force; clearing the cap alone
  declares about 160 GiB against your volume and the first stream exhausts it.
{{- else }}
  JetStream is running at full declared retention, no per-stream cap: about
  160 GiB across the streams. nats.persistence.size must accommodate that or
  the aggregator dies on its first stream with err_code=10047.
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
  hack/preflight.sh          (or: make preflight)

  It probes storage, privileged-workload admission, NetworkPolicy ENFORCEMENT
  and each optional source against this cluster, and prints the exact remedy
  flag for each one. It changes nothing.
{{- end -}}
