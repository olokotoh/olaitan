package posture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/olokotoh/olaitan/internal/keys"
	"github.com/olokotoh/olaitan/internal/schema"
)

// defaultServiceAccount is the implicit K8s admission default. A pod
// with spec.serviceAccountName empty is admitted with ServiceAccount
// "default" in the pod's namespace; the posture client treats the
// empty case as "default" so RBAC bound to the default SA is surfaced
// for the LLM-bound payload.
const defaultServiceAccount = "default"

// listPageLimit caps each List call to a single page. fetch loops
// continue until the apiserver's continue token is empty, so a
// namespace with >500 bindings does not silently truncate the
// posture surface.
const listPageLimit = 500

// DefaultCacheTTL is the default posture cache staleness budget.
// architecture.md:324 pins this at 60 seconds; AC3 ratifies the
// ceiling. The Helm chart fails render if posture.cacheTTL exceeds
// this constant.
const DefaultCacheTTL = 60 * time.Second

// MaxCacheTTL is the architectural ceiling on cache staleness.
// Configurations above this are rejected at Validate; the chart
// enforces the same ceiling at render time via mustRegexFind+fail.
const MaxCacheTTL = 60 * time.Second

// DefaultFetchTimeout caps the per-Get K8s API context. Posture is
// on the investigation-chain critical path so an unbounded fetch
// would compound LLM budget pressure (architecture.md:324 reads
// "Cache TTL 60 seconds"; the fetch budget is independent).
const DefaultFetchTimeout = 5 * time.Second

// MaxRoleVerbsCap and MaxRoleResourcesCap bound the union surface a
// posture struct carries per binding. The cap exists to keep the LLM
// prompt size bounded; a Role with 200 verbs would otherwise compose
// a 5 KiB binding ref.
const (
	MaxRoleVerbsCap     = 32
	MaxRoleResourcesCap = 32
)

// Config configures a Client. Validate is called by New; partial or
// zero blocks accept defaults so an operator can omit the values
// block entirely.
type Config struct {
	// CacheTTL is the maximum staleness for cached postures. Helm
	// value: posture.cacheTTL. Default 60s. Rejected at validate if
	// <= 0 or > MaxCacheTTL (architecture.md:324 + AC3 ceiling).
	CacheTTL time.Duration

	// FetchTimeout is the per-Get context timeout. Default 5s.
	FetchTimeout time.Duration

	// NowFn is the test-seam for clock injection. nil means
	// time.Now in production.
	NowFn func() time.Time
}

// Validate enforces Config invariants. Zero/negative durations are
// rejected; durations above the architectural ceiling are rejected.
func (c *Config) Validate() error {
	if c.CacheTTL <= 0 {
		return errors.New("posture: cache_ttl must be > 0")
	}
	if c.CacheTTL > MaxCacheTTL {
		return fmt.Errorf("posture: cache_ttl must be <= %s (architecture.md:324 ceiling; got %s)", MaxCacheTTL, c.CacheTTL)
	}
	if c.FetchTimeout <= 0 {
		return errors.New("posture: fetch_timeout must be > 0")
	}
	return nil
}

// DefaultConfig returns a Config with the architectural defaults
// applied. Callers compose this with their own Config and pass the
// merged value to New.
func DefaultConfig() Config {
	return Config{
		CacheTTL:     DefaultCacheTTL,
		FetchTimeout: DefaultFetchTimeout,
	}
}

// Client is the read-on-demand workload posture client. The Client
// is safe for concurrent calls; Get acquires read-locks on the
// cache and write-locks only on stale-evict / refresh.
type Client struct {
	cs           kubernetes.Interface
	cache        *cache
	cacheTTL     time.Duration
	fetchTimeout time.Duration
	nowFn        func() time.Time
	log          *slog.Logger

	cacheHits     atomic.Int64
	cacheMisses   atomic.Int64
	cacheBypasses atomic.Int64
	apiErrors     atomic.Int64
	orphanPods    atomic.Int64
	unavailable   atomic.Int64
}

// New constructs a Client. Validate is called on cfg; cs must be
// non-nil. log defaults to slog.Default() when nil.
func New(cfg Config, cs kubernetes.Interface, log *slog.Logger) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cs == nil {
		return nil, errors.New("posture: clientset is nil")
	}
	if log == nil {
		log = slog.Default()
	}
	nowFn := cfg.NowFn
	if nowFn == nil {
		nowFn = time.Now
	}
	c := &Client{
		cs:           cs,
		cache:        newCache(),
		cacheTTL:     cfg.CacheTTL,
		fetchTimeout: cfg.FetchTimeout,
		nowFn:        nowFn,
		log:          log.With(slog.String("component", "posture")),
	}
	return c, nil
}

// Option mutates a getOptions. Callers compose options via the
// With* constructors and pass them to Get.
type Option func(*getOptions)

type getOptions struct {
	bypassCache    bool
	bypassCacheFor string
}

// WithBypassCache forces a fresh K8s-API round trip for this Get,
// bypassing any cached posture. The Story 3.x orchestrator's
// "fresh-fetch on LLM-eligible package" policy
// (architecture.md:326) consumes this option for severity >= 50
// or baseline_max_deviation >= 3σ packages.
func WithBypassCache() Option {
	return func(o *getOptions) { o.bypassCache = true }
}

// WithBypassCacheFor scopes the bypass to a specific workload
// identity. Useful when a caller wants to invalidate a specific
// workload's cache entry after a posture-mutating event without
// affecting other cached entries. workloadID is the canonical
// "<namespace>/<owner-kind>/<owner-name>" form returned by
// keys.WorkloadID.
func WithBypassCacheFor(workloadID string) Option {
	return func(o *getOptions) { o.bypassCacheFor = workloadID }
}

// Get returns the posture for the workload represented by pod.
//
// Algorithm:
//
//  1. Resolve workload identity via ResolveWorkloadIdentity. On
//     error, return a partial WorkloadPosture with Unavailable=true
//     plus the classification error.
//  2. Compute the cache key via keys.WorkloadID (or
//     keys.PodFallbackID for orphan pods).
//  3. Unless bypass is requested, attempt a cache read.
//  4. On miss (or bypass), fetch bindings + network policies +
//     SecurityContext projections from the K8s API, assemble, cache.
//
// The error return distinguishes Unavailable=true (partial struct
// returned) from caller errors (nil struct returned). Callers that
// only care about a best-effort posture can ignore the error and
// inspect Unavailable + UnavailableReason on the struct.
func (c *Client) Get(ctx context.Context, pod *corev1.Pod, opts ...Option) (*schema.WorkloadPosture, error) {
	if pod == nil {
		return nil, errors.New("posture: pod is nil")
	}

	options := &getOptions{}
	for _, opt := range opts {
		opt(options)
	}

	// Owner resolution issues up to two K8s API GETs (architecture.md
	// :457 + Story 1.11 guardrail 23). Apply the per-Get fetch budget
	// here so an unhealthy apiserver cannot block resolution past the
	// LLM critical-path window. The fetchPosture call below uses the
	// same fetchCtx so the total budget covers both phases.
	fetchCtx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()

	identity, err := ResolveWorkloadIdentity(fetchCtx, c.cs, pod)
	if err != nil && !errors.Is(err, ErrControllerNotFound) {
		c.apiErrors.Add(1)
		c.unavailable.Add(1)
		class := classify(err)
		c.log.Error("posture: owner resolution failed",
			slog.String("namespace", pod.Namespace),
			slog.String("pod_name", pod.Name),
			slog.String("error_class", class),
			slog.String("error", err.Error()),
		)
		// Synthesise an orphan-pod-shaped identity so the
		// correlator can still log workload_id, and set OrphanPod
		// to mirror that synthesis. Without this, consumers branch
		// on OrphanPod=false while Identity.OwnerKind="Pod" — an
		// inconsistent payload that the schema docstring explicitly
		// forbids.
		return &schema.WorkloadPosture{
			Identity: schema.WorkloadIdentity{
				Namespace: pod.Namespace,
				OwnerKind: "Pod",
				OwnerName: pod.Name,
				PodName:   pod.Name,
			},
			OrphanPod:         true,
			Unavailable:       true,
			UnavailableReason: class,
			CapturedAt:        c.nowFn(),
		}, err
	}
	if errors.Is(err, ErrControllerNotFound) {
		// Surface the controller-NotFound classification for
		// operator visibility before falling through to the
		// orphan-pod fallback path.
		c.log.Info("posture: controller not found, falling back to orphan-pod identity",
			slog.String("namespace", pod.Namespace),
			slog.String("pod_name", pod.Name),
			slog.String("error", err.Error()),
		)
	}

	isOrphan := identity.OwnerKind == "Pod"
	if isOrphan {
		c.orphanPods.Add(1)
	}

	workloadID, err := c.workloadIDFor(identity)
	if err != nil {
		c.apiErrors.Add(1)
		c.log.Error("posture: workload-id builder failed",
			slog.String("namespace", identity.Namespace),
			slog.String("owner_kind", identity.OwnerKind),
			slog.String("owner_name", identity.OwnerName),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	bypass := options.bypassCache || (options.bypassCacheFor != "" && options.bypassCacheFor == workloadID)
	if bypass {
		c.cacheBypasses.Add(1)
	} else {
		if cached, ok := c.cache.Get(workloadID, c.nowFn); ok {
			c.cacheHits.Add(1)
			// Defensive copy: the cache stores a single pointer
			// per workload and any consumer mutation would leak
			// into subsequent Get callers. Return a shallow clone
			// so the cached entry is read-only from the caller's
			// perspective.
			return cloneWorkloadPosture(cached), nil
		}
		c.cacheMisses.Add(1)
	}

	posture, fetchErr := c.fetchPosture(fetchCtx, pod, identity, isOrphan)
	if fetchErr != nil {
		c.apiErrors.Add(1)
		c.unavailable.Add(1)
		class := classify(fetchErr)
		c.log.Error("posture: fetch failed",
			slog.String("workload_id", workloadID),
			slog.String("error_class", class),
			slog.String("error", fetchErr.Error()),
		)
		// Build a partial posture preserving the resolved identity
		// so the correlator can still log workload_id, then mark
		// unavailable for the LLM-bound payload.
		partial := basePosture(identity, isOrphan, c.nowFn())
		partial.Unavailable = true
		partial.UnavailableReason = class
		return partial, fetchErr
	}

	c.cache.Put(workloadID, posture, c.cacheTTL, c.nowFn)
	// Return a clone so concurrent readers do not race on the
	// pointer stored inside the cache.
	return cloneWorkloadPosture(posture), nil
}

// workloadIDFor builds the canonical cache key for an identity,
// honouring the orphan-pod fallback per architecture.md:457.
func (c *Client) workloadIDFor(id schema.WorkloadIdentity) (string, error) {
	if id.OwnerKind == "Pod" {
		return keys.PodFallbackID(id.Namespace, id.OwnerName)
	}
	return keys.WorkloadID(id.Namespace, id.OwnerKind, id.OwnerName)
}

// basePosture allocates a posture with identity and CapturedAt set;
// downstream paths populate bindings/policies/SecurityContext.
func basePosture(identity schema.WorkloadIdentity, isOrphan bool, capturedAt time.Time) *schema.WorkloadPosture {
	return &schema.WorkloadPosture{
		Identity:   identity,
		OrphanPod:  isOrphan,
		CapturedAt: capturedAt,
	}
}

// fetchPosture is the K8s-API fan-out: lists role-bindings, cluster-
// role-bindings, and network policies; projects SecurityContext from
// the pod argument directly. All errors propagate so the caller can
// classify and mark Unavailable.
func (c *Client) fetchPosture(ctx context.Context, pod *corev1.Pod, identity schema.WorkloadIdentity, isOrphan bool) (*schema.WorkloadPosture, error) {
	posture := basePosture(identity, isOrphan, c.nowFn())
	// Store the effective ServiceAccount on the posture struct so the
	// LLM-bound payload reflects the same identity the RBAC lookups
	// resolved against. K8s admission rewrites an empty
	// spec.serviceAccountName to "default" before the pod runs; the
	// posture surface must mirror that so consumers do not see
	// service_account:"" while RoleBindings/ClusterRoleBindings carry
	// the default-SA bindings.
	posture.ServiceAccount = effectiveServiceAccount(pod.Spec.ServiceAccountName)

	roleBindings, err := c.listRoleBindings(ctx, pod.Namespace, posture.ServiceAccount)
	if err != nil {
		return nil, fmt.Errorf("list rolebindings: %w", err)
	}
	posture.RoleBindings = roleBindings

	clusterRoleBindings, err := c.listClusterRoleBindings(ctx, pod.Namespace, posture.ServiceAccount)
	if err != nil {
		return nil, fmt.Errorf("list clusterrolebindings: %w", err)
	}
	posture.ClusterRoleBindings = clusterRoleBindings

	policies, err := ApplicableNetworkPolicies(ctx, c.cs, pod.Namespace, pod.Labels)
	if err != nil {
		return nil, fmt.Errorf("list networkpolicies: %w", err)
	}
	posture.NetworkPolicies = summariseNetworkPolicies(policies)

	posture.PodSecurityContext = summarisePodSecurityContext(pod.Spec.SecurityContext)
	posture.ContainerSecurityContexts = summariseContainerSecurityContexts(pod)

	return posture, nil
}

// effectiveServiceAccount returns the ServiceAccount name the K8s
// admission controller would have assigned to the pod. An empty
// pod.spec.serviceAccountName is replaced with "default" so the
// posture client surfaces RBAC bound to the implicit default SA
// (a common attack-surface target).
func effectiveServiceAccount(sa string) string {
	if sa == "" {
		return defaultServiceAccount
	}
	return sa
}

// listRoleBindings returns the namespaced RoleBindings whose subjects
// include the given ServiceAccount or a group that transitively
// includes it (system:serviceaccounts, system:serviceaccounts:<ns>,
// system:authenticated). For each match, the referenced Role (or
// ClusterRole) is fetched and its verbs/resources flattened into the
// union surface, capped at MaxRoleVerbsCap entries.
//
// The List call paginates via Limit/Continue so namespaces with
// >listPageLimit bindings do not silently truncate. Each binding is
// inspected after its page lands; the per-page cost is bounded by
// listPageLimit.
func (c *Client) listRoleBindings(ctx context.Context, namespace, serviceAccount string) ([]schema.RoleBindingRef, error) {
	sa := effectiveServiceAccount(serviceAccount)
	out := []schema.RoleBindingRef{}
	cont := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		list, err := c.cs.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{
			Limit:    listPageLimit,
			Continue: cont,
		})
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			rb := &list.Items[i]
			if !subjectsContainServiceAccount(rb.Subjects, namespace, sa) {
				continue
			}
			ref := schema.RoleBindingRef{
				Name:     rb.Name,
				RoleKind: rb.RoleRef.Kind,
				RoleName: rb.RoleRef.Name,
			}
			verbs, resources, truncated, lookupErr := c.lookupRoleSurface(ctx, namespace, rb.RoleRef.Kind, rb.RoleRef.Name)
			if lookupErr != nil {
				// Best-effort: surface the binding even when the
				// role fetch fails, but flag VerbsUnavailable so
				// the LLM can distinguish "binding exists with
				// no rules" from "binding exists, rules unknown".
				c.log.Warn("posture: rolebinding role lookup failed",
					slog.String("namespace", namespace),
					slog.String("rolebinding", rb.Name),
					slog.String("role_kind", rb.RoleRef.Kind),
					slog.String("role_name", rb.RoleRef.Name),
					slog.String("error", lookupErr.Error()),
				)
				ref.VerbsUnavailable = true
			}
			ref.Verbs = verbs
			ref.Resources = resources
			ref.VerbsTruncated = truncated
			out = append(out, ref)
		}
		cont = list.Continue
		if cont == "" {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// listClusterRoleBindings returns the ClusterRoleBindings whose
// subjects include the given ServiceAccount with the workload's
// namespace, or a group that transitively includes it. The List call
// paginates via Limit/Continue.
func (c *Client) listClusterRoleBindings(ctx context.Context, namespace, serviceAccount string) ([]schema.ClusterRoleBindingRef, error) {
	sa := effectiveServiceAccount(serviceAccount)
	out := []schema.ClusterRoleBindingRef{}
	cont := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		list, err := c.cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{
			Limit:    listPageLimit,
			Continue: cont,
		})
		if err != nil {
			return nil, err
		}
		for i := range list.Items {
			crb := &list.Items[i]
			if !subjectsContainServiceAccount(crb.Subjects, namespace, sa) {
				continue
			}
			ref := schema.ClusterRoleBindingRef{
				Name:     crb.Name,
				RoleName: crb.RoleRef.Name,
			}
			verbs, resources, truncated, lookupErr := c.lookupRoleSurface(ctx, "", "ClusterRole", crb.RoleRef.Name)
			if lookupErr != nil {
				c.log.Warn("posture: clusterrolebinding role lookup failed",
					slog.String("clusterrolebinding", crb.Name),
					slog.String("role_name", crb.RoleRef.Name),
					slog.String("error", lookupErr.Error()),
				)
				ref.VerbsUnavailable = true
			}
			ref.Verbs = verbs
			ref.Resources = resources
			ref.VerbsTruncated = truncated
			out = append(out, ref)
		}
		cont = list.Continue
		if cont == "" {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// lookupRoleSurface fetches a Role or ClusterRole by name and
// flattens its rules into the verbs/resources union, capped per
// guardrail. truncated reports whether bounded had to trim either
// slice; callers surface this on RoleBindingRef.VerbsTruncated so the
// LLM consumer can tell that the surface is incomplete.
func (c *Client) lookupRoleSurface(ctx context.Context, namespace, kind, name string) (verbs, resources []string, truncated bool, err error) {
	verbSet := make(map[string]struct{})
	resSet := make(map[string]struct{})
	switch kind {
	case "Role":
		role, fetchErr := c.cs.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
		if fetchErr != nil {
			return nil, nil, false, fetchErr
		}
		for _, rule := range role.Rules {
			for _, v := range rule.Verbs {
				verbSet[v] = struct{}{}
			}
			for _, r := range rule.Resources {
				resSet[r] = struct{}{}
			}
		}
	case "ClusterRole":
		cr, fetchErr := c.cs.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
		if fetchErr != nil {
			return nil, nil, false, fetchErr
		}
		for _, rule := range cr.Rules {
			for _, v := range rule.Verbs {
				verbSet[v] = struct{}{}
			}
			for _, r := range rule.Resources {
				resSet[r] = struct{}{}
			}
		}
	default:
		return nil, nil, false, fmt.Errorf("posture: unknown role kind %q", kind)
	}

	verbs, verbsTruncated := bounded(verbSet, MaxRoleVerbsCap)
	resources, resourcesTruncated := bounded(resSet, MaxRoleResourcesCap)
	return verbs, resources, verbsTruncated || resourcesTruncated, nil
}

// bounded converts a set to a sorted slice capped at limit. truncated
// reports whether the original set exceeded limit (so a caller can
// surface the truncation on the wire schema).
func bounded(set map[string]struct{}, limit int) ([]string, bool) {
	if len(set) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) > limit {
		return out[:limit], true
	}
	return out, false
}

// subjectsContainServiceAccount returns true when any subject in the
// binding's Subjects slice grants the workload's ServiceAccount
// permission. Three subject shapes resolve to the SA:
//
//  1. Kind=ServiceAccount, Name=<sa>, Namespace=<ns> — direct binding.
//  2. Kind=Group, Name=system:serviceaccounts — bound to every SA
//     in the cluster.
//  3. Kind=Group, Name=system:serviceaccounts:<ns> — bound to every
//     SA in the workload's namespace.
//  4. Kind=Group, Name=system:authenticated — bound to every
//     authenticated principal, which includes every SA.
//
// Without (2)/(3)/(4), bindings that transitively grant cluster-admin-
// equivalent privileges via the well-known service-account groups
// would be silently dropped from the posture surface and the LLM
// consumer would under-report effective RBAC.
func subjectsContainServiceAccount(subjects []rbacv1.Subject, namespace, serviceAccount string) bool {
	nsGroup := "system:serviceaccounts:" + namespace
	for _, s := range subjects {
		switch s.Kind {
		case "ServiceAccount":
			if s.Name == serviceAccount && s.Namespace == namespace {
				return true
			}
		case "Group":
			switch s.Name {
			case "system:serviceaccounts",
				"system:authenticated",
				nsGroup:
				return true
			}
		}
	}
	return false
}

// summariseNetworkPolicies projects networkingv1.NetworkPolicy into
// schema.NetworkPolicyRef summaries.
func summariseNetworkPolicies(policies []networkingv1.NetworkPolicy) []schema.NetworkPolicyRef {
	if len(policies) == 0 {
		return nil
	}
	out := make([]schema.NetworkPolicyRef, 0, len(policies))
	for _, np := range policies {
		ptypes := make([]string, 0, len(np.Spec.PolicyTypes))
		for _, pt := range np.Spec.PolicyTypes {
			ptypes = append(ptypes, string(pt))
		}
		out = append(out, schema.NetworkPolicyRef{
			Name:         np.Name,
			PolicyTypes:  ptypes,
			IngressRules: len(np.Spec.Ingress),
			EgressRules:  len(np.Spec.Egress),
		})
	}
	return out
}

// summarisePodSecurityContext projects corev1.PodSecurityContext.
// Returns nil when the pod has no pod-level security context.
func summarisePodSecurityContext(psc *corev1.PodSecurityContext) *schema.PodSecurityContextSummary {
	if psc == nil {
		return nil
	}
	out := &schema.PodSecurityContextSummary{
		RunAsUser:          psc.RunAsUser,
		RunAsGroup:         psc.RunAsGroup,
		RunAsNonRoot:       psc.RunAsNonRoot,
		FSGroup:            psc.FSGroup,
		SupplementalGroups: psc.SupplementalGroups,
	}
	if psc.SeccompProfile != nil {
		out.SeccompProfile = string(psc.SeccompProfile.Type)
	}
	if psc.SELinuxOptions != nil {
		out.SELinuxLevel = psc.SELinuxOptions.Level
	}
	return out
}

// summariseContainerSecurityContexts projects per-container
// SecurityContexts across init, regular, and ephemeral containers.
// A container with no SecurityContext set is preserved as an entry
// with Inherits=true so the LLM consumer can distinguish "container
// inherits pod-level defaults" (a posture finding in its own right)
// from "container does not exist in the pod".
func summariseContainerSecurityContexts(pod *corev1.Pod) []schema.ContainerSecurityContextSummary {
	out := make([]schema.ContainerSecurityContextSummary, 0)
	for i := range pod.Spec.InitContainers {
		out = appendContainer(out, &pod.Spec.InitContainers[i], schema.ContainerKindInit)
	}
	for i := range pod.Spec.Containers {
		out = appendContainer(out, &pod.Spec.Containers[i], schema.ContainerKindRegular)
	}
	for i := range pod.Spec.EphemeralContainers {
		ec := &pod.Spec.EphemeralContainers[i]
		out = append(out, projectContainerSecurityContext(ec.Name, schema.ContainerKindEphemeral, ec.SecurityContext))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// appendContainer projects a single container's SecurityContext and
// appends the resulting summary (with Inherits=true when sc is nil).
func appendContainer(out []schema.ContainerSecurityContextSummary, ctr *corev1.Container, kind string) []schema.ContainerSecurityContextSummary {
	return append(out, projectContainerSecurityContext(ctr.Name, kind, ctr.SecurityContext))
}

// projectContainerSecurityContext maps corev1.SecurityContext (or
// the ephemeral variant) to schema.ContainerSecurityContextSummary.
// A nil SecurityContext produces a summary with Inherits=true and
// all other fields nil so the consumer knows the container is
// inheriting pod-level settings unmodified.
func projectContainerSecurityContext(name, kind string, sc *corev1.SecurityContext) schema.ContainerSecurityContextSummary {
	summary := schema.ContainerSecurityContextSummary{
		ContainerName: name,
		Kind:          kind,
	}
	if sc == nil {
		summary.Inherits = true
		return summary
	}
	summary.Privileged = sc.Privileged
	summary.AllowPrivilegeEscalation = sc.AllowPrivilegeEscalation
	summary.ReadOnlyRootFilesystem = sc.ReadOnlyRootFilesystem
	summary.RunAsUser = sc.RunAsUser
	summary.RunAsGroup = sc.RunAsGroup
	summary.RunAsNonRoot = sc.RunAsNonRoot
	if sc.Capabilities != nil {
		for _, c := range sc.Capabilities.Add {
			summary.AddedCapabilities = append(summary.AddedCapabilities, string(c))
		}
		for _, c := range sc.Capabilities.Drop {
			summary.DroppedCapabilities = append(summary.DroppedCapabilities, string(c))
		}
	}
	if sc.SeccompProfile != nil {
		summary.SeccompProfile = string(sc.SeccompProfile.Type)
	}
	return summary
}

// classify maps a K8s API error to one of the four UnavailableReason
// classes per AC4 + NFR15. The returned class is what flows into the
// LLM-bound posture payload; the raw err.Error() is logged separately.
//
// Beyond the four typed apierrors checks, this also handles:
//
//   - 401 Unauthorized → permission_denied (apierrors.IsUnauthorized).
//     A revoked or rotated token is a permissions failure from the
//     workload's perspective, not a permanent fault.
//   - 429 Too Many Requests → transient (apierrors.IsTooManyRequests).
//     The K8s Priority and Fairness signal is a retry-after-backoff
//     class, not a permanent fault.
//   - net.Error timeouts and connection-refused / EOF / TLS-handshake
//     errors → transient. These are raised by the rest-client at the
//     transport layer and never wrap as IsTimeout(); classifying them
//     as "permanent" would falsely tell the LLM the workload is
//     permanently un-postureable during a kube-apiserver restart.
//   - net/url.Error wrapping a timeout → transient.
func classify(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
		return schema.PostureUnavailablePermissionDenied
	case apierrors.IsNotFound(err):
		return schema.PostureUnavailableNotFound
	case apierrors.IsTimeout(err),
		apierrors.IsServerTimeout(err),
		apierrors.IsServiceUnavailable(err),
		apierrors.IsTooManyRequests(err):
		return schema.PostureUnavailableTransient
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return schema.PostureUnavailableTransient
	}
	// Transport-layer errors: net.Error.Timeout, dial-refused, EOF,
	// TLS handshake timeout, url.Error-wrapped timeouts. None of
	// these are typed apierrors, so we inspect via errors.As + a
	// last-resort string match against well-known suffixes from
	// net/http's transport layer.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return schema.PostureUnavailableTransient
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return schema.PostureUnavailableTransient
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "EOF"),
		strings.Contains(msg, "TLS handshake timeout"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "i/o timeout"):
		return schema.PostureUnavailableTransient
	}
	return schema.PostureUnavailablePermanent
}

// cloneWorkloadPosture returns a deep clone of p with independent
// slice headers at every nesting level and a fresh PodSecurityContext
// pointer. The cache stores a single pointer per workload and any
// caller mutation would leak across subsequent Get calls; cloning at
// Get time keeps the cached entry read-only from the caller's
// perspective. Nested string slices on each ref (Verbs, Resources,
// PolicyTypes, Added/DroppedCapabilities, SupplementalGroups) are
// also cloned so a caller appending to the slice header of a
// RoleBindingRef.Verbs does not race the next cache read.
func cloneWorkloadPosture(p *schema.WorkloadPosture) *schema.WorkloadPosture {
	if p == nil {
		return nil
	}
	out := *p
	if p.RoleBindings != nil {
		out.RoleBindings = make([]schema.RoleBindingRef, len(p.RoleBindings))
		for i, rb := range p.RoleBindings {
			out.RoleBindings[i] = rb
			out.RoleBindings[i].Verbs = cloneStrings(rb.Verbs)
			out.RoleBindings[i].Resources = cloneStrings(rb.Resources)
		}
	}
	if p.ClusterRoleBindings != nil {
		out.ClusterRoleBindings = make([]schema.ClusterRoleBindingRef, len(p.ClusterRoleBindings))
		for i, crb := range p.ClusterRoleBindings {
			out.ClusterRoleBindings[i] = crb
			out.ClusterRoleBindings[i].Verbs = cloneStrings(crb.Verbs)
			out.ClusterRoleBindings[i].Resources = cloneStrings(crb.Resources)
		}
	}
	if p.NetworkPolicies != nil {
		out.NetworkPolicies = make([]schema.NetworkPolicyRef, len(p.NetworkPolicies))
		for i, np := range p.NetworkPolicies {
			out.NetworkPolicies[i] = np
			out.NetworkPolicies[i].PolicyTypes = cloneStrings(np.PolicyTypes)
		}
	}
	if p.ContainerSecurityContexts != nil {
		out.ContainerSecurityContexts = make([]schema.ContainerSecurityContextSummary, len(p.ContainerSecurityContexts))
		for i, c := range p.ContainerSecurityContexts {
			out.ContainerSecurityContexts[i] = c
			out.ContainerSecurityContexts[i].AddedCapabilities = cloneStrings(c.AddedCapabilities)
			out.ContainerSecurityContexts[i].DroppedCapabilities = cloneStrings(c.DroppedCapabilities)
		}
	}
	if p.PodSecurityContext != nil {
		psc := *p.PodSecurityContext
		if psc.SupplementalGroups != nil {
			psc.SupplementalGroups = append([]int64(nil), psc.SupplementalGroups...)
		}
		out.PodSecurityContext = &psc
	}
	return &out
}

// cloneStrings returns a fresh slice with the same elements; nil
// stays nil so the cloned WorkloadPosture matches the original's
// "absent" vs "empty" semantics under JSON marshal.
func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// PostureCacheHits returns the cumulative cache-hit count. Story
// 1.12 binds this getter to the Prometheus counter
// olaitan_sensor_posture_cache_hit_total.
func (c *Client) PostureCacheHits() int64 { return c.cacheHits.Load() }

// PostureCacheMisses returns the cumulative cache-miss count. A
// miss is a cache-eligible Get with no fresh entry; explicit
// bypass-cache calls do not contribute to this counter (they are
// counted separately via PostureCacheBypasses) so the hit-rate KPI
// reflects natural cache eligibility, not LLM-eligible refetch
// policy.
func (c *Client) PostureCacheMisses() int64 { return c.cacheMisses.Load() }

// PostureCacheBypasses returns the cumulative count of Get calls
// that bypassed the cache via WithBypassCache or WithBypassCacheFor.
// Story 1.12 binds this getter to a Prometheus counter so operators
// can observe LLM-eligible fresh-fetch volume independently of the
// natural hit/miss split.
func (c *Client) PostureCacheBypasses() int64 { return c.cacheBypasses.Load() }

// PostureAPIErrors returns the cumulative K8s-API-error count.
func (c *Client) PostureAPIErrors() int64 { return c.apiErrors.Load() }

// PostureOrphanPods returns the cumulative orphan-pod fallback count.
func (c *Client) PostureOrphanPods() int64 { return c.orphanPods.Load() }

// PostureUnavailable returns the cumulative count of Get calls that
// returned a posture with Unavailable=true.
func (c *Client) PostureUnavailable() int64 { return c.unavailable.Load() }
