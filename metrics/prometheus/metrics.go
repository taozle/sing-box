package prometheus

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	promlib "github.com/prometheus/client_golang/prometheus"
	"github.com/sagernet/sing-box/adapter"
)

type metricsSet struct {
	connections      *promlib.GaugeVec
	connectionsTotal *promlib.CounterVec
	durations        *promlib.HistogramVec
	trafficBytes     *promlib.CounterVec
}

func newMetricsSet(registry *promlib.Registry) *metricsSet {
	metrics := &metricsSet{
		connections: promlib.NewGaugeVec(promlib.GaugeOpts{
			Namespace: "sing_box",
			Name:      "active_connections",
			Help:      "Number of active proxy connections",
		}, []string{"inbound", "inbound_type", "outbound", "outbound_type", "rule", "network"}),
		connectionsTotal: promlib.NewCounterVec(promlib.CounterOpts{
			Namespace: "sing_box",
			Name:      "connections_total",
			Help:      "Total number of proxy connections created",
		}, []string{"inbound", "inbound_type", "outbound", "outbound_type", "rule", "network"}),
		durations: promlib.NewHistogramVec(promlib.HistogramOpts{
			Namespace: "sing_box",
			Name:      "connection_duration_seconds",
			Help:      "Duration of proxy connections in seconds",
		}, []string{"inbound", "inbound_type", "outbound", "outbound_type", "rule", "network"}),
		trafficBytes: promlib.NewCounterVec(promlib.CounterOpts{
			Namespace: "sing_box",
			Name:      "connection_bytes_total",
			Help:      "Traffic volume by proxy connection direction",
		}, []string{"inbound", "inbound_type", "outbound", "outbound_type", "rule", "network", "direction"}),
	}
	registry.MustRegister(metrics.connections, metrics.connectionsTotal, metrics.durations, metrics.trafficBytes)
	return metrics
}

func (m *metricsSet) observeConnectionStart(labels []string) {
	m.connections.WithLabelValues(labels...).Inc()
	m.connectionsTotal.WithLabelValues(labels...).Inc()
}

func (m *metricsSet) observeConnectionClose(labels []string, duration time.Duration) {
	m.connections.WithLabelValues(labels...).Dec()
	m.durations.WithLabelValues(labels...).Observe(duration.Seconds())
}

func (m *metricsSet) observeTraffic(labels []string, direction string, bytes int64) {
	if bytes <= 0 {
		return
	}
	values := append(append([]string(nil), labels...), direction)
	m.trafficBytes.WithLabelValues(values...).Add(float64(bytes))
}

type dnsMetricsSet struct {
	requests   *promlib.CounterVec
	durations  *promlib.HistogramVec
	topDomains *topDomainTracker
}

func newDNSMetricsSet(registry *promlib.Registry) *dnsMetricsSet {
	metrics := &dnsMetricsSet{
		requests: promlib.NewCounterVec(promlib.CounterOpts{
			Namespace: "sing_box",
			Name:      "dns_requests_total",
			Help:      "Number of DNS queries handled by the proxy",
		}, []string{"inbound", "inbound_type", "transport", "transport_type", "rule", "rcode", "qtype", "cached"}),
		durations: promlib.NewHistogramVec(promlib.HistogramOpts{
			Namespace: "sing_box",
			Name:      "dns_request_duration_seconds",
			Help:      "Latency of proxied DNS queries in seconds",
		}, []string{"inbound", "inbound_type", "transport", "transport_type", "rule", "rcode", "qtype", "cached"}),
	}
	metrics.topDomains = newTopDomainTracker(registry)
	registry.MustRegister(metrics.requests, metrics.durations, metrics.topDomains.gauge)
	return metrics
}

func (m *dnsMetricsSet) observe(observation adapter.DNSQueryObservation) {
	metadata := observation.Metadata
	inbound := "-"
	inboundType := "-"
	if metadata != nil {
		if metadata.Inbound != "" {
			inbound = metadata.Inbound
		}
		if metadata.InboundType != "" {
			inboundType = metadata.InboundType
		}
	}
	transport := "-"
	transportType := "-"
	if observation.Transport != nil {
		transport = safeLabel(observation.Transport.Tag())
		transportType = safeLabel(observation.Transport.Type())
	}
	rule := "-"
	if observation.Rule != nil {
		rule = safeLabel(observation.Rule.Type())
	}
	rcode := rcodeLabel(observation)
	qtype := questionType(observation.Question.Qtype)
	cached := boolLabel(observation.Cached)
	labels := []string{inbound, inboundType, transport, transportType, rule, rcode, qtype, cached}
	m.requests.WithLabelValues(labels...).Inc()
	if observation.Duration > 0 {
		m.durations.WithLabelValues(labels...).Observe(observation.Duration.Seconds())
	}
	domain := ""
	if metadata != nil {
		domain = metadata.Domain
	}
	if domain == "" && observation.Question.Name != "" {
		domain = normalizeDomain(observation.Question.Name)
	}
	m.topDomains.Observe(domain)
}

func safeLabel(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func questionType(value uint16) string {
	if name, ok := dns.TypeToString[value]; ok {
		return name
	}
	return strconvFormatUint(uint64(value))
}

func boolLabel(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func rcodeLabel(observation adapter.DNSQueryObservation) string {
	if observation.Err != nil {
		return "error"
	}
	if observation.RCode >= 0 {
		if name, ok := dns.RcodeToString[observation.RCode]; ok {
			return name
		}
		return strconvFormatUint(uint64(observation.RCode))
	}
	return "-"
}

type topDomainTracker struct {
	gauge  *promlib.GaugeVec
	size   int
	mu     sync.Mutex
	counts map[string]uint64
	top    []domainCount
}

type domainCount struct {
	domain string
	count  uint64
}

func newTopDomainTracker(registry *promlib.Registry) *topDomainTracker {
	gauge := promlib.NewGaugeVec(promlib.GaugeOpts{
		Namespace: "sing_box",
		Name:      "dns_top_domain_requests",
		Help:      "Top DNS query domains observed by the proxy",
	}, []string{"domain"})
	tracker := &topDomainTracker{
		gauge:  gauge,
		size:   10,
		counts: make(map[string]uint64),
	}
	return tracker
}

func (t *topDomainTracker) Observe(domain string) {
	if domain == "" {
		return
	}
	domain = strings.ToLower(domain)
	t.mu.Lock()
	defer t.mu.Unlock()
	count := t.counts[domain] + 1
	t.counts[domain] = count
	updated := false
	for i := range t.top {
		if t.top[i].domain == domain {
			t.top[i].count = count
			updated = true
			break
		}
	}
	if !updated {
		if len(t.top) < t.size {
			t.top = append(t.top, domainCount{domain: domain, count: count})
			updated = true
		} else if count > t.top[len(t.top)-1].count {
			removed := t.top[len(t.top)-1]
			t.gauge.DeleteLabelValues(removed.domain)
			t.top[len(t.top)-1] = domainCount{domain: domain, count: count}
			updated = true
		}
	}
	if updated {
		sort.Slice(t.top, func(i, j int) bool {
			if t.top[i].count == t.top[j].count {
				return t.top[i].domain < t.top[j].domain
			}
			return t.top[i].count > t.top[j].count
		})
		for _, entry := range t.top {
			t.gauge.WithLabelValues(entry.domain).Set(float64(entry.count))
		}
	}
}

func normalizeDomain(name string) string {
	if name == "" {
		return ""
	}
	trimmed := strings.TrimSuffix(name, ".")
	return strings.ToLower(trimmed)
}

func strconvFormatUint(value uint64) string {
	return strconv.FormatUint(value, 10)
}
