package falco

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/olokotoh/olaitan/internal/collector/falco/falcopb"
)

// internalSource and metricsSnapshotRule identify Falco's periodic metrics
// snapshot, which the adapter consumes as a liveness heartbeat and never
// publishes. Only that rule: Falco's other internal events, such as
// "Falco internal: syscall event drop", are security signal (flooding
// syscalls is how an attacker blinds Falco) and are published like alerts.
const (
	internalSource      = "internal"
	metricsSnapshotRule = "Falco internal: metrics snapshot"
)

// httpAlert is the JSON body Falco's http_output POSTs for one event when
// json_output is true. Field names are Falco's, not ours.
//
// output_fields is decoded as raw JSON on purpose. Its values are strings,
// numbers, booleans or null depending on the field, and some numbers are
// 19-digit nanosecond timestamps that float64 cannot hold exactly
// (1789102842544857414 decodes as ...344). Keeping the raw bytes lets
// fieldString render each value from Falco's own text.
type httpAlert struct {
	Hostname     string                     `json:"hostname"`
	Output       string                     `json:"output"`
	OutputFields map[string]json.RawMessage `json:"output_fields"`
	Priority     string                     `json:"priority"`
	Rule         string                     `json:"rule"`
	Source       string                     `json:"source"`
	Tags         []string                   `json:"tags"`
	Time         string                     `json:"time"`
}

// priorityByName maps Falco's priority names to the proto enum. Falco
// writes them capitalised ("Warning"); lookup is case-insensitive.
var priorityByName = map[string]falcopb.Priority{
	"emergency":     falcopb.Priority_EMERGENCY,
	"alert":         falcopb.Priority_ALERT,
	"critical":      falcopb.Priority_CRITICAL,
	"error":         falcopb.Priority_ERROR,
	"warning":       falcopb.Priority_WARNING,
	"notice":        falcopb.Priority_NOTICE,
	"informational": falcopb.Priority_INFORMATIONAL,
	"info":          falcopb.Priority_INFORMATIONAL,
	"debug":         falcopb.Priority_DEBUG,
}

// unknownPriority is outside the enum's 0..7 range. The zero value would
// read as EMERGENCY, so an unrecognised name is mapped here instead;
// Translate then logs it once and scores it as informational.
const unknownPriority = falcopb.Priority(-1)

// DecodeHTTPOutput turns one Falco http_output body into the same
// falcopb.Response the gRPC output used to deliver, so Translate and
// everything downstream of it are unchanged by the transport swap.
//
// Falco 0.44.0 removed the gRPC output (falcosecurity/falco#3798), and
// the Falco releases that run on kernel 7.x are all newer than that.
// Keeping the proto message as the in-memory model means an event
// translates to the same ID and the same Raw bytes it did before.
func DecodeHTTPOutput(body []byte) (*falcopb.Response, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var in httpAlert
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("falco: decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("falco: decode: trailing data after the alert object")
	}
	if in.Rule == "" {
		return nil, errors.New("falco: decode: alert has no rule")
	}
	if in.Time == "" {
		return nil, fmt.Errorf("falco: decode: alert has no time (rule=%q)", in.Rule)
	}
	ts, err := time.Parse(time.RFC3339Nano, in.Time)
	if err != nil {
		return nil, fmt.Errorf("falco: decode: time %q (rule=%q): %w", in.Time, in.Rule, err)
	}

	fields := make(map[string]string, len(in.OutputFields))
	for k, v := range in.OutputFields {
		s, ok, err := fieldString(v)
		if err != nil {
			return nil, fmt.Errorf("falco: decode: output_fields[%q]: %w", k, err)
		}
		if ok {
			fields[k] = s
		}
	}

	prio, known := priorityByName[strings.ToLower(in.Priority)]
	if !known {
		prio = unknownPriority
	}

	return &falcopb.Response{
		Time:         timestamppb.New(ts),
		Priority:     prio,
		Source:       in.Source,
		Rule:         in.Rule,
		Output:       in.Output,
		OutputFields: fields,
		Hostname:     in.Hostname,
		Tags:         in.Tags,
	}, nil
}

// fieldString renders one output_fields value as the string the gRPC
// output carried. ok is false for JSON null: Falco had no value, and
// dropping the key leaves a missing pod name empty rather than "null".
func fieldString(v json.RawMessage) (s string, ok bool, err error) {
	t := bytes.TrimSpace(v)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return "", false, nil
	}
	if t[0] == '"' {
		if err := json.Unmarshal(t, &s); err != nil {
			return "", false, err
		}
		return s, true, nil
	}
	// Numbers, booleans, arrays and objects keep Falco's own text.
	if !json.Valid(t) {
		return "", false, errors.New("invalid JSON value")
	}
	return string(t), true, nil
}
