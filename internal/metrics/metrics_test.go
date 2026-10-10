package metrics

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestCounterAndSummary(t *testing.T) {
	r := NewCounter("sentinel_test_total", "test counter.", "method", "route")
	r.Inc("GET", "/v1/identities")
	r.Inc("GET", "/v1/identities")
	r.Add(2.5, "POST", "/v1/connectors")

	s := NewSummary("sentinel_test_duration_seconds", "latency.", "method")
	s.Observe(100*time.Millisecond, "GET")
	s.Observe(50*time.Millisecond, "GET")

	var buf bytes.Buffer
	writeCounter(&buf, r.labelled)
	writeCounter(&buf, s.sum)
	writeCounter(&buf, s.count)
	out := buf.String()
	if out == "" {
		t.Fatal("empty exposition")
	}
	for _, want := range []string{
		"# HELP sentinel_test_total test counter.",
		"# TYPE sentinel_test_total counter",
		`sentinel_test_total{method="GET",route="/v1/identities"} 2`,
		`sentinel_test_total{method="POST",route="/v1/connectors"} 2.5`,
		"sentinel_test_duration_seconds_sum",
		"sentinel_test_duration_seconds_count",
		"# TYPE sentinel_test_duration_seconds_count summary",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "sentinel_test_duration_seconds_sum") {
		t.Fatal("summary sum missing")
	}
}

func TestEscape(t *testing.T) {
	if got := escape(`a"b\c` + "\n"); got != `a\"b\\c\n` {
		t.Fatalf("escape: %q", got)
	}
}

func TestGlobalRegistry(t *testing.T) {
	var buf bytes.Buffer
	WritePrometheus(&buf)
	// The global metrics exist with help/type lines.
	for _, want := range []string{
		"sentinel_http_requests_total",
		"sentinel_http_request_duration_seconds",
		"sentinel_connector_runs_total",
		"sentinel_connector_run_duration_seconds",
		"sentinel_scheduler_ticks_total",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing global metric %q", want)
		}
	}
}

func TestConcurrentIncrements(t *testing.T) {
	c := NewCounter("sentinel_concurrent_total", "c.", "label")
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				c.Inc("x")
				if n%2 == 0 {
					c.Inc("y")
				}
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	var buf bytes.Buffer
	writeCounter(&buf, c.labelled)
	if !strings.Contains(buf.String(), `sentinel_concurrent_total{label="x"} 1600`) {
		t.Fatal("concurrent counter value wrong")
	}
	if !strings.Contains(buf.String(), `sentinel_concurrent_total{label="y"} 800`) {
		t.Fatal("concurrent y value wrong")
	}
}
