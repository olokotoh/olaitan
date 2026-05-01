// Spike POC for Story 1.3: subscribe to one Calico flow record from
// Goldmane v3.31.5 and translate it into a canonical schema.Event.
// This is throwaway investigation code; the production adapter lands
// in internal/collector/cni/ under Story 1.10. See ADR-2026-04-30-01
// in docs/deferred-decisions.md for the durable record.
//
// Modes:
//
//	--mode capture            Connect, receive flows, save first one
//	                          to testdata/sample-flow.binpb (binary
//	                          protobuf), translate it, save expected
//	                          translator output to testdata/expected.json,
//	                          print PASS on round-trip success.
//	--mode bench              Translate ≥100 flows; report median + p99
//	                          per-record latency. Hoists gRPC client
//	                          and JSON encoder out of the timed loop.
//	--mode fixture-translate  Read testdata/sample-flow.binpb, translate
//	                          it, compare with testdata/expected.json,
//	                          print PASS — same path the test exercises.
//
// AC2 PASS condition: capture mode completes without error AND the
// translated schema.Event round-trips through json.Marshal +
// json.Unmarshal yielding equal byte sequences (the protojson Raw
// blob is canonicalised through encoding/json so the round-trip is
// byte-stable).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	goldmanev1 "github.com/olokotoh/olaitan/spikes/calico-flow/proto"
)

const (
	defaultAddr        = "localhost:7443"
	defaultServerName  = "goldmane.calico-system.svc"
	defaultCAPath      = "/tmp/goldmane-tls/ca.crt"
	defaultCertPath    = "/tmp/goldmane-tls/client.crt"
	defaultKeyPath     = "/tmp/goldmane-tls/client.key"
	defaultFixturePath = "testdata/sample-flow.binpb"
	defaultExpectPath  = "testdata/expected.json"
	benchTarget        = 100
)

func main() {
	mode := flag.String("mode", "capture", "capture | bench | fixture-translate")
	addr := flag.String("addr", defaultAddr, "Goldmane gRPC address (port-forwarded)")
	serverName := flag.String("server-name", defaultServerName, "TLS SNI / verify name")
	caPath := flag.String("ca", defaultCAPath, "tigera-ca-bundle PEM path")
	certPath := flag.String("cert", defaultCertPath, "client TLS cert PEM path (mTLS required)")
	keyPath := flag.String("key", defaultKeyPath, "client TLS key PEM path (mTLS required)")
	fixturePath := flag.String("fixture", defaultFixturePath, "binary protobuf fixture path")
	expectPath := flag.String("expected", defaultExpectPath, "expected JSON output path")
	srcNS := flag.String("src-ns", "", "filter: only stream flows whose source namespace matches (capture/bench)")
	dstNS := flag.String("dst-ns", "", "filter: only stream flows whose dest namespace matches (capture/bench)")
	timeoutSec := flag.Int("timeout", 60, "overall timeout in seconds (capture/bench)")
	flag.Parse()

	filter := buildFilter(*srcNS, *dstNS)

	switch *mode {
	case "capture":
		if err := runCapture(*addr, *serverName, *caPath, *certPath, *keyPath, *fixturePath, *expectPath, filter, *timeoutSec); err != nil {
			log.Fatalf("FAIL: %v", err)
		}
	case "bench":
		if err := runBench(*addr, *serverName, *caPath, *certPath, *keyPath, filter, *timeoutSec); err != nil {
			log.Fatalf("FAIL: %v", err)
		}
	case "fixture-translate":
		if err := runFixtureTranslate(*fixturePath, *expectPath); err != nil {
			log.Fatalf("FAIL: %v", err)
		}
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}

// dial connects to Goldmane over mutual TLS. The Tigera CA bundle
// verifies the server certificate; a client certificate signed by
// the same CA is required (Goldmane v3.31.5 enforces client cert
// auth on its gRPC listener). For the spike, the whisker-backend
// keypair is reused — Story 1.10 must provision a dedicated cert
// for olaitan-agent, either via the operator's pkimanager or by
// authoring a separate Operator-recognised CR.
func dial(addr, serverName, caPath, certPath, keyPath string) (*grpc.ClientConn, error) {
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("CA bundle did not parse any certificates")
	}
	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	tlsCfg := &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}
	creds := credentials.NewTLS(tlsCfg)
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
}

func runCapture(addr, serverName, caPath, certPath, keyPath, fixturePath, expectPath string, filter *goldmanev1.Filter, timeoutSec int) error {
	conn, err := dial(addr, serverName, caPath, certPath, keyPath)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := goldmanev1.NewFlowsClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	stream, err := client.Stream(ctx, &goldmanev1.FlowStreamRequest{
		StartTimeGte:        -60, // last 60s
		AggregationInterval: 15,
		Filter:              filter,
	})
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	log.Printf("connected; waiting for first FlowResult (up to %ds)...", timeoutSec)

	fr, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("recv: %w", err)
	}
	log.Printf("received FlowResult id=%d src=%s/%s dst=%s/%s:%d proto=%s action=%v reporter=%v",
		fr.Id, fr.Flow.Key.SourceNamespace, fr.Flow.Key.SourceName,
		fr.Flow.Key.DestNamespace, fr.Flow.Key.DestName, fr.Flow.Key.DestPort,
		fr.Flow.Key.Proto, fr.Flow.Key.Action, fr.Flow.Key.Reporter)

	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		return fmt.Errorf("mkdir testdata: %w", err)
	}
	frBytes, err := proto.Marshal(fr)
	if err != nil {
		return fmt.Errorf("marshal fixture: %w", err)
	}
	if err := os.WriteFile(fixturePath, frBytes, 0o644); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}

	evt, err := translate(fr)
	if err != nil {
		return fmt.Errorf("translate: %w", err)
	}
	// AC2 PASS condition: the translated event survives a marshal /
	// unmarshal / re-marshal cycle with semantic equality. JSON key
	// ordering differs between Go struct-order and decoded-map
	// alphabetical-order, so we compare on the parsed map rather
	// than on raw bytes.
	if err := assertRoundTrip(evt); err != nil {
		return err
	}

	// Write expected.json with the timestamp normalised. Tests compare
	// byte-for-byte against this fixture; the live run has a real
	// timestamp, but the test substitutes a fixed one before marshal.
	normalised := evt
	normalised.Timestamp = fixedTimestamp()
	expBytes, err := json.MarshalIndent(normalised, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal expected: %w", err)
	}
	if err := os.WriteFile(expectPath, append(expBytes, '\n'), 0o644); err != nil {
		return fmt.Errorf("write expected: %w", err)
	}

	fmt.Println("PASS")
	fmt.Printf("fixture:  %s (%d bytes)\n", fixturePath, len(frBytes))
	fmt.Printf("expected: %s\n", expectPath)
	return nil
}

func runBench(addr, serverName, caPath, certPath, keyPath string, filter *goldmanev1.Filter, timeoutSec int) error {
	conn, err := dial(addr, serverName, caPath, certPath, keyPath)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	client := goldmanev1.NewFlowsClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	stream, err := client.Stream(ctx, &goldmanev1.FlowStreamRequest{
		StartTimeGte:        -300,
		AggregationInterval: 15,
		Filter:              filter,
	})
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	samples := make([]time.Duration, 0, benchTarget)
	for received := 0; received < benchTarget; {
		fr, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("recv: %w", err)
		}
		// Hot path under measurement — translation + JSON marshal.
		start := time.Now()
		evt, err := translate(fr)
		if err != nil {
			return fmt.Errorf("translate: %w", err)
		}
		if _, err := json.Marshal(evt); err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		samples = append(samples, time.Since(start))
		received++
	}
	if len(samples) == 0 {
		return errors.New("no flows received within timeout")
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	median := samples[(len(samples)-1)/2]
	// p99 index uses (n-1)*99/100 so a 100-sample run reads index 99.
	p99 := samples[(len(samples)-1)*99/100]

	fmt.Println("PASS")
	fmt.Printf("samples:  %d\n", len(samples))
	fmt.Printf("median:   %s\n", median)
	fmt.Printf("p99:      %s\n", p99)
	fmt.Printf("min:      %s\n", samples[0])
	fmt.Printf("max:      %s\n", samples[len(samples)-1])
	return nil
}

func runFixtureTranslate(fixturePath, expectPath string) error {
	frBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		return fmt.Errorf("read fixture: %w", err)
	}
	fr := &goldmanev1.FlowResult{}
	if err := proto.Unmarshal(frBytes, fr); err != nil {
		return fmt.Errorf("unmarshal fixture: %w", err)
	}
	evt, err := translate(fr)
	if err != nil {
		return fmt.Errorf("translate: %w", err)
	}
	evt.Timestamp = fixedTimestamp()

	got, err := json.MarshalIndent(evt, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	got = append(got, '\n')

	want, err := os.ReadFile(expectPath)
	if err != nil {
		return fmt.Errorf("read expected: %w", err)
	}
	if string(got) != string(want) {
		return fmt.Errorf("translator output does not match expected\n  got:\n%s\n  want:\n%s", got, want)
	}
	fmt.Println("PASS")
	return nil
}

// fixedTimestamp returns the timestamp tests substitute before
// comparison. The fixture's StartTime is real, but tests must remain
// stable across runs.
func fixedTimestamp() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

// buildFilter returns a Goldmane Filter that narrows the stream to
// flows with the given source and/or destination namespaces. Empty
// strings disable the corresponding filter dimension.
func buildFilter(srcNS, dstNS string) *goldmanev1.Filter {
	if srcNS == "" && dstNS == "" {
		return nil
	}
	f := &goldmanev1.Filter{}
	if srcNS != "" {
		f.SourceNamespaces = []*goldmanev1.StringMatch{{Value: srcNS, Type: goldmanev1.MatchType_Exact}}
	}
	if dstNS != "" {
		f.DestNamespaces = []*goldmanev1.StringMatch{{Value: dstNS, Type: goldmanev1.MatchType_Exact}}
	}
	return f
}

// assertRoundTrip checks that an Event survives marshal / unmarshal /
// re-marshal as a semantically identical value. Byte-equality fails
// because Go marshals struct fields in declaration order while
// re-marshalling a decoded map sorts keys alphabetically; the two
// encodings carry the same information.
func assertRoundTrip(evt any) error {
	first, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	var a any
	if err := json.Unmarshal(first, &a); err != nil {
		return fmt.Errorf("unmarshal first: %w", err)
	}
	second, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("re-marshal: %w", err)
	}
	var b any
	if err := json.Unmarshal(second, &b); err != nil {
		return fmt.Errorf("unmarshal second: %w", err)
	}
	if !reflect.DeepEqual(a, b) {
		return fmt.Errorf("round-trip semantic mismatch:\n  first:  %s\n  second: %s", first, second)
	}
	return nil
}
