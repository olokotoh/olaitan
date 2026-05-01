package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/olokotoh/olaitan/internal/schema"
	goldmanev1 "github.com/olokotoh/olaitan/spikes/calico-flow/proto"
)

// translate converts a Goldmane FlowResult into the canonical
// internal/schema.Event the rest of Olaitan consumes. The translation
// is intentionally minimal — Story 1.10 inherits the contract this
// function defines and decides whether to enrich workload identity
// inline (K8s API lookups) or downstream in the correlator.
func translate(fr *goldmanev1.FlowResult) (schema.Event, error) {
	if fr == nil || fr.Flow == nil || fr.Flow.Key == nil {
		return schema.Event{}, fmt.Errorf("translate: nil flow result")
	}
	flow := fr.Flow
	key := flow.Key

	// FR13 workload identity — namespace/owner-kind/owner-name with
	// orphan-pod fallback. Goldmane's FlowKey.source_name is a
	// GenerateName-derived identifier ("a set of pods that share a
	// GenerateName"), so this Pod ref is a *set* identity rather than
	// a single pod. Story 1.10 must enrich via the K8s API to recover
	// owner-kind/owner-name; the correlator (Story 1.14) sees the
	// enriched value, not this raw set name.
	pod := schema.PodRef{
		Name:      key.SourceName,
		Namespace: key.SourceNamespace,
	}

	// Event timestamp uses Flow.StartTime (Unix seconds). Goldmane
	// aggregates over a 15s minimum window, so this is the start of
	// the aggregation interval rather than per-packet wall-time.
	ts := time.Unix(flow.StartTime, 0).UTC()

	// Event ID synthesises FlowResult.Id with the start time so the
	// same flow at two different aggregation windows yields distinct
	// IDs. FlowResult.Id is documented to NOT be valid across server
	// restarts, so the start_time component is the durable half.
	id := fmt.Sprintf("calico-flow-%d-%d", flow.StartTime, fr.Id)

	// Marshal the original FlowResult to JSON for the Raw blob.
	// protojson.Marshal is the canonical JSON encoding for protobuf
	// messages and round-trips cleanly through json.Unmarshal.
	rawBytes, err := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
	}.Marshal(fr)
	if err != nil {
		return schema.Event{}, fmt.Errorf("translate: marshal raw: %w", err)
	}
	// Re-marshal through encoding/json to canonicalise whitespace —
	// protojson emits non-deterministic spacing across versions.
	var rawObj map[string]any
	if err := json.Unmarshal(rawBytes, &rawObj); err != nil {
		return schema.Event{}, fmt.Errorf("translate: re-decode raw: %w", err)
	}
	canonRaw, err := json.Marshal(rawObj)
	if err != nil {
		return schema.Event{}, fmt.Errorf("translate: re-marshal raw: %w", err)
	}

	tags := buildTags(key, flow)

	summary := fmt.Sprintf("%s/%s -> %s/%s:%d (%s, %s, %s)",
		nonEmpty(key.SourceNamespace, "-"),
		nonEmpty(key.SourceName, "-"),
		nonEmpty(key.DestNamespace, "-"),
		nonEmpty(key.DestName, "-"),
		key.DestPort,
		strings.ToLower(key.Proto),
		actionString(key.Action),
		reporterString(key.Reporter),
	)

	return schema.Event{
		ID:        id,
		Timestamp: ts,
		Source:    schema.SourceNetwork,
		Pod:       pod,
		Category:  schema.CategoryFlow,
		Summary:   summary,
		Raw:       canonRaw,
		Tags:      tags,
	}, nil
}

func buildTags(key *goldmanev1.FlowKey, flow *goldmanev1.Flow) []string {
	tags := []string{
		"proto:" + strings.ToLower(key.Proto),
		"action:" + actionString(key.Action),
		"reporter:" + reporterString(key.Reporter),
		"src-type:" + endpointTypeString(key.SourceType),
		"dst-type:" + endpointTypeString(key.DestType),
		"dst-port:" + strconv.FormatInt(key.DestPort, 10),
	}
	if key.DestServiceName != "" {
		tags = append(tags, "svc:"+key.DestServiceNamespace+"/"+key.DestServiceName)
	}
	if flow.NumConnectionsStarted > 0 {
		tags = append(tags, "conns-started:"+strconv.FormatInt(flow.NumConnectionsStarted, 10))
	}
	return tags
}

func actionString(a goldmanev1.Action) string {
	switch a {
	case goldmanev1.Action_Allow:
		return "allow"
	case goldmanev1.Action_Deny:
		return "deny"
	case goldmanev1.Action_Pass:
		return "pass"
	default:
		return "unspecified"
	}
}

func reporterString(r goldmanev1.Reporter) string {
	switch r {
	case goldmanev1.Reporter_Src:
		return "src"
	case goldmanev1.Reporter_Dst:
		return "dst"
	default:
		return "unspecified"
	}
}

func endpointTypeString(t goldmanev1.EndpointType) string {
	switch t {
	case goldmanev1.EndpointType_WorkloadEndpoint:
		return "workload"
	case goldmanev1.EndpointType_HostEndpoint:
		return "host"
	case goldmanev1.EndpointType_NetworkSet:
		return "networkset"
	case goldmanev1.EndpointType_Network:
		return "network"
	default:
		return "unspecified"
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
