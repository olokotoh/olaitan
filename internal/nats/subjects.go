package nats

// NATS subject hierarchy for inter-ring communication.
const (
	// Ring 1 → Ring 2: raw events per source
	SubjectRawFalco   = "olaitan.events.raw.falco"
	SubjectRawAudit   = "olaitan.events.raw.audit"
	SubjectRawRuntime = "olaitan.events.raw.runtime"
	SubjectRawNetwork = "olaitan.events.raw.network"
	SubjectRawAppLog  = "olaitan.events.raw.applog"

	// Ring 1 → Ring 2: normalised events (common schema)
	SubjectNormalised = "olaitan.events.normalised"

	// Ring 2 → Ring 3: correlated event groups per pod
	// Use SubjectCorrelated(namespace, pod) for specific subjects
	SubjectCorrelatedPrefix = "olaitan.correlated."

	// Ring 3 → Ring 4: threat assessments by severity band
	SubjectThreatsWatch   = "olaitan.threats.watch"
	SubjectThreatsAlert   = "olaitan.threats.alert"
	SubjectThreatsAct     = "olaitan.threats.act"
	SubjectThreatsIsolate = "olaitan.threats.isolate"

	// Ring 4: state transitions per pod
	// Use SubjectState(namespace, pod) for specific subjects
	SubjectStatePrefix = "olaitan.state."

	// Health: per-ring health status
	// Use SubjectHealth(ring) for specific subjects
	SubjectHealthPrefix    = "olaitan.health."
	SubjectHealthHeartbeat = "olaitan.health.heartbeat"
)

// SubjectCorrelated returns the NATS subject for a specific pod's correlated events.
func SubjectCorrelated(namespace, pod string) string {
	return SubjectCorrelatedPrefix + namespace + "." + pod
}

// SubjectState returns the NATS subject for a specific pod's state transitions.
func SubjectState(namespace, pod string) string {
	return SubjectStatePrefix + namespace + "." + pod
}

// SubjectHealth returns the NATS subject for a specific ring's health status.
func SubjectHealth(ring string) string {
	return SubjectHealthPrefix + ring
}
