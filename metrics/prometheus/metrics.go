package prometheus

import (
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	connectionLabelNames = []string{"network", "inbound", "inbound_type", "outbound", "outbound_type", "rule"}
	trafficLabelNames    = []string{"direction", "network", "inbound", "inbound_type", "outbound", "outbound_type", "rule"}
	connectionBuckets    = []float64{0.25, 1, 5, 15, 60, 300, 900, 3600, 21600, 86400}

	dnsRequestLabelNames  = []string{"server", "server_type", "rule", "cache", "rcode", "qtype"}
	dnsDurationLabelNames = []string{"server", "server_type", "rule", "rcode", "qtype"}
)

const (
	labelValueUnknown = "unknown"
	labelValueDefault = "default"
	labelValueNone    = "none"
	labelValueCache   = "cache"
	labelValueError   = "error"
	directionUplink   = "uplink"
	directionDownlink = "downlink"

	cacheLabelHit  = "hit"
	cacheLabelMiss = "miss"

	dnsTopDomainLimit    = 10
	dnsMaxTrackedDomains = 256
)

type metricsSet struct {
	connections      *prometheus.GaugeVec
	connectionsTotal *prometheus.CounterVec
	durations        *prometheus.HistogramVec
	trafficBytes     *prometheus.CounterVec
}

type dnsMetricsSet struct {
	requests   *prometheus.CounterVec
	durations  *prometheus.HistogramVec
	topDomains *prometheus.GaugeVec

	access         sync.Mutex
	domainCounts   map[string]uint64
	topDomainRanks map[int]string
}

func newMetricsSet(registry *prometheus.Registry) *metricsSet {
	metrics := &metricsSet{
		connections: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "sing_box",
			Name:      "connections",
			Help:      "Number of active routed connections.",
		}, connectionLabelNames),
		connectionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sing_box",
			Name:      "connections_total",
			Help:      "Total number of routed connections.",
		}, connectionLabelNames),
		durations: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "sing_box",
			Name:      "connection_duration_seconds",
			Help:      "Connection duration distribution.",
			Buckets:   connectionBuckets,
		}, connectionLabelNames),
		trafficBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sing_box",
			Name:      "traffic_bytes_total",
			Help:      "Traffic volume of routed connections.",
		}, trafficLabelNames),
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

func (m *metricsSet) observeTraffic(labels []string, bytes int64) {
	if bytes <= 0 {
		return
	}
	m.trafficBytes.WithLabelValues(labels...).Add(float64(bytes))
}

func newDNSMetricsSet(registry *prometheus.Registry) *dnsMetricsSet {
	metrics := &dnsMetricsSet{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sing_box",
			Name:      "dns_requests_total",
			Help:      "Total number of DNS requests handled by the router.",
		}, dnsRequestLabelNames),
		durations: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "sing_box",
			Name:      "dns_request_duration_seconds",
			Help:      "DNS request duration distribution.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
		}, dnsDurationLabelNames),
		topDomains: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "sing_box",
			Name:      "dns_top_domain_requests_total",
			Help:      "Top DNS query domains ranked by request count.",
		}, []string{"rank", "domain"}),
		domainCounts:   make(map[string]uint64),
		topDomainRanks: make(map[int]string),
	}
	registry.MustRegister(metrics.requests, metrics.durations, metrics.topDomains)
	return metrics
}

func (m *dnsMetricsSet) observe(cacheLabel, server, serverType, rule, rcode, qtype, domain string, duration time.Duration, cached bool) {
	m.requests.WithLabelValues(server, serverType, rule, cacheLabel, rcode, qtype).Inc()
	if !cached {
		m.durations.WithLabelValues(server, serverType, rule, rcode, qtype).Observe(duration.Seconds())
	}
	if domain != "" {
		m.updateTopDomains(domain)
	}
}

func (m *dnsMetricsSet) updateTopDomains(domain string) {
	m.access.Lock()
	defer m.access.Unlock()

	if count, exists := m.domainCounts[domain]; exists {
		m.domainCounts[domain] = count + 1
	} else {
		if len(m.domainCounts) >= dnsMaxTrackedDomains {
			var (
				minDomain string
				minCount  uint64
				found     bool
			)
			for existingDomain, existingCount := range m.domainCounts {
				if !found || existingCount < minCount {
					minDomain = existingDomain
					minCount = existingCount
					found = true
				}
			}
			if found {
				delete(m.domainCounts, minDomain)
				for rank, trackedDomain := range m.topDomainRanks {
					if trackedDomain == minDomain {
						m.topDomains.DeleteLabelValues(strconv.Itoa(rank), trackedDomain)
						delete(m.topDomainRanks, rank)
					}
				}
			}
		}
		m.domainCounts[domain] = 1
	}

	type domainEntry struct {
		domain string
		count  uint64
	}

	entries := make([]domainEntry, 0, len(m.domainCounts))
	for trackedDomain, count := range m.domainCounts {
		entries = append(entries, domainEntry{domain: trackedDomain, count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count == entries[j].count {
			return entries[i].domain < entries[j].domain
		}
		return entries[i].count > entries[j].count
	})
	if len(entries) > dnsTopDomainLimit {
		entries = entries[:dnsTopDomainLimit]
	}

	for rank, entry := range entries {
		rankIndex := rank + 1
		labelRank := strconv.Itoa(rankIndex)
		if previousDomain, exists := m.topDomainRanks[rankIndex]; exists && previousDomain != entry.domain {
			m.topDomains.DeleteLabelValues(labelRank, previousDomain)
		}
		m.topDomains.WithLabelValues(labelRank, entry.domain).Set(float64(entry.count))
		m.topDomainRanks[rankIndex] = entry.domain
	}
	for rank := len(entries) + 1; rank <= dnsTopDomainLimit; rank++ {
		if previousDomain, exists := m.topDomainRanks[rank]; exists {
			m.topDomains.DeleteLabelValues(strconv.Itoa(rank), previousDomain)
			delete(m.topDomainRanks, rank)
		}
	}
}
