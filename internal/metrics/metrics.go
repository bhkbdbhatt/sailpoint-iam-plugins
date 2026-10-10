// Package metrics exposes a small, dependency-free Prometheus-compatible
// metric registry for the HTTP layer, the connector runner and the scheduler.
package metrics

import (
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const keySep = "\x1f"

// labelled stores labelled float64 samples.
type labelled struct {
	mu     sync.Mutex
	name   string
	help   string
	labels []string
	values map[string]float64
}

func newLabelled(name, help string, labels ...string) *labelled {
	return &labelled{name: name, help: help, labels: labels, values: map[string]float64{}}
}

func (l *labelled) key(vals []string) string {
	return strings.Join(vals, keySep)
}

func (l *labelled) inc(vals ...string) {
	l.add(1, vals...)
}

func (l *labelled) add(v float64, vals ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.key(vals)
	l.values[k] += v
}

// Counter is a monotonically increasing labelled counter.
type Counter struct{ *labelled }

func NewCounter(name, help string, labels ...string) *Counter {
	return &Counter{newLabelled(name, help, labels...)}
}

func (c *Counter) Inc(vals ...string)            { c.inc(vals...) }
func (c *Counter) Add(v float64, vals ...string) { c.add(v, vals...) }

// Summary tracks count and sum of observations per label set.
type Summary struct {
	sum   *labelled
	count *labelled
}

func NewSummary(name, help string, labels ...string) *Summary {
	return &Summary{
		sum:   newLabelled(name+"_sum", help, labels...),
		count: newLabelled(name+"_count", help, labels...),
	}
}

func (s *Summary) Observe(d time.Duration, vals ...string) {
	s.sum.add(d.Seconds(), vals...)
	s.count.inc(vals...)
}

var (
	RequestsTotal    = NewCounter("sentinel_http_requests_total", "HTTP requests by route and status.", "method", "route", "status")
	RequestsSeconds  = NewSummary("sentinel_http_request_duration_seconds", "HTTP request latency in seconds.", "method", "route")
	ConnectorRuns    = NewCounter("sentinel_connector_runs_total", "Connector runs by key and status.", "key", "status")
	ConnectorSeconds = NewSummary("sentinel_connector_run_duration_seconds", "Connector run latency in seconds.", "key")
	SchedulerTicks   = NewCounter("sentinel_scheduler_ticks_total", "Scheduler wake-ups.", "interval")
)

// WritePrometheus renders the registry in the Prometheus text exposition format.
func WritePrometheus(w io.Writer) {
	writeCounter(w, RequestsTotal.labelled)
	writeCounter(w, RequestsSeconds.sum)
	writeCounter(w, RequestsSeconds.count)
	writeCounter(w, ConnectorRuns.labelled)
	writeCounter(w, ConnectorSeconds.sum)
	writeCounter(w, ConnectorSeconds.count)
	writeCounter(w, SchedulerTicks.labelled)
}

func writeCounter(w io.Writer, l *labelled) {
	l.mu.Lock()
	samples := make([]struct {
		key string
		val float64
	}, 0, len(l.values))
	for k, v := range l.values {
		samples = append(samples, struct {
			key string
			val float64
		}{k, v})
	}
	l.mu.Unlock()

	sort.Slice(samples, func(i, j int) bool { return samples[i].key < samples[j].key })

	_, _ = io.WriteString(w, "# HELP "+l.name+" "+l.help+"\n")
	kind := "counter"
	if strings.HasSuffix(l.name, "_sum") || strings.HasSuffix(l.name, "_count") {
		kind = "summary"
	}
	_, _ = io.WriteString(w, "# TYPE "+l.name+" "+kind+"\n")
	for _, s := range samples {
		writeSeries(w, l, strings.Split(s.key, keySep), s.val)
	}
}

func writeSeries(w io.Writer, l *labelled, vals []string, value float64) {
	var sb strings.Builder
	sb.WriteString(l.name)
	if len(l.labels) > 0 {
		sb.WriteByte('{')
		for i, label := range l.labels {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(label)
			sb.WriteString(`="`)
			sb.WriteString(escape(vals[i]))
			sb.WriteString(`"`)
		}
		sb.WriteByte('}')
	}
	sb.WriteByte(' ')
	sb.WriteString(strconv.FormatFloat(value, 'g', -1, 64))
	sb.WriteByte('\n')
	_, _ = io.WriteString(w, sb.String())
}

func escape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}
