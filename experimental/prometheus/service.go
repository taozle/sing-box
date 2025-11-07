package prometheus

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	_ adapter.PrometheusService = (*Service)(nil)
)

type Service struct {
	ctx       context.Context
	cancel    context.CancelFunc
	createdAt time.Time

	access   sync.Mutex
	counters map[string]*atomic.Int64

	// Prometheus metrics
	trafficBytes      *prometheus.CounterVec
	connectionsTotal  prometheus.Counter
	activeConnections *prometheus.GaugeVec
	dnsQueries        *prometheus.CounterVec
	uptime            prometheus.Gauge
	goroutines        prometheus.Gauge
	memAlloc          prometheus.Gauge
	memSys            prometheus.Gauge
	gcRuns            prometheus.Gauge

	registry *prometheus.Registry
}

func NewService(ctx context.Context, options option.PrometheusOptions) (*Service, error) {
	if !options.Enabled {
		return nil, nil
	}

	registry := prometheus.NewRegistry()

	service := &Service{
		createdAt: time.Now(),
		counters:  make(map[string]*atomic.Int64),
		registry:  registry,
	}

	// Initialize Prometheus metrics
	service.trafficBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "singbox_traffic_bytes_total",
			Help: "Total bytes transferred",
		},
		[]string{"type", "tag", "direction"},
	)

	service.connectionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "singbox_connections_total",
			Help: "Total number of connections handled",
		},
	)

	service.activeConnections = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "singbox_active_connections",
			Help: "Current number of active connections",
		},
		[]string{"inbound", "outbound"},
	)

	service.uptime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "singbox_uptime_seconds",
			Help: "Uptime in seconds",
		},
	)

	service.goroutines = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "singbox_goroutines",
			Help: "Number of goroutines",
		},
	)

	service.memAlloc = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "singbox_memory_alloc_bytes",
			Help: "Bytes of allocated heap objects",
		},
	)

	service.memSys = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "singbox_memory_sys_bytes",
			Help: "Total bytes of memory obtained from the OS",
		},
	)

	service.gcRuns = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "singbox_gc_runs_total",
			Help: "Total number of GC runs",
		},
	)

	service.dnsQueries = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "singbox_dns_queries_total",
			Help: "Total number of DNS queries",
		},
		[]string{"transport", "domain", "type", "status"},
	)

	// Register metrics
	registry.MustRegister(
		service.trafficBytes,
		service.connectionsTotal,
		service.activeConnections,
		service.dnsQueries,
		service.uptime,
		service.goroutines,
		service.memAlloc,
		service.memSys,
		service.gcRuns,
	)

	service.ctx, service.cancel = context.WithCancel(ctx)

	return service, nil
}

func (s *Service) Name() string {
	return "prometheus"
}

func (s *Service) Start(stage adapter.StartStage) error {
	if s == nil {
		return nil
	}

	if stage != adapter.StartStateStart {
		return nil
	}

	// Start system stats collector
	go s.collectSystemStats()

	return nil
}

func (s *Service) Close() error {
	if s == nil {
		return nil
	}

	s.cancel()
	return nil
}

// Handler returns the HTTP handler for Prometheus metrics endpoint
func (s *Service) Handler() http.Handler {
	if s == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{})
}

func (s *Service) collectSystemStats() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.updateSystemStats()
		}
	}
}

func (s *Service) updateSystemStats() {
	// Update uptime
	s.uptime.Set(time.Since(s.createdAt).Seconds())

	// Update goroutines
	s.goroutines.Set(float64(runtime.NumGoroutine()))

	// Update memory stats
	var rtm runtime.MemStats
	runtime.ReadMemStats(&rtm)
	s.memAlloc.Set(float64(rtm.Alloc))
	s.memSys.Set(float64(rtm.Sys))
	s.gcRuns.Set(float64(rtm.NumGC))

	// Update traffic metrics from counters
	s.access.Lock()
	defer s.access.Unlock()

	for name, counter := range s.counters {
		value := float64(counter.Load())

		// Parse counter name to extract labels
		// Format: "inbound>>>tag>>>traffic>>>direction"
		// or "outbound>>>tag>>>traffic>>>direction"
		// or "user>>>name>>>traffic>>>direction"
		if parsed := parseCounterName(name); parsed != nil {
			s.trafficBytes.With(prometheus.Labels{
				"type":      parsed.counterType,
				"tag":       parsed.tag,
				"direction": parsed.direction,
			}).Add(value)

			// Reset counter after reading
			counter.Store(0)
		}
	}
}

type parsedCounter struct {
	counterType string // "inbound", "outbound", "user"
	tag         string
	direction   string // "uplink", "downlink"
}

func parseCounterName(name string) *parsedCounter {
	// Simple string parsing
	// Format: "type>>>tag>>>traffic>>>direction"
	parts := splitString(name, ">>>")
	if len(parts) != 4 || parts[2] != "traffic" {
		return nil
	}

	return &parsedCounter{
		counterType: parts[0],
		tag:         parts[1],
		direction:   parts[3],
	}
}

func splitString(s, sep string) []string {
	var result []string
	start := 0
	sepLen := len(sep)

	for i := 0; i <= len(s)-sepLen; i++ {
		if s[i:i+sepLen] == sep {
			result = append(result, s[start:i])
			start = i + sepLen
			i += sepLen - 1
		}
	}

	result = append(result, s[start:])
	return result
}

func (s *Service) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	if s == nil {
		return conn
	}

	inbound := metadata.Inbound
	user := metadata.User
	outbound := matchOutbound.Tag()

	var readCounter []*atomic.Int64
	var writeCounter []*atomic.Int64

	s.access.Lock()
	if inbound != "" {
		readCounter = append(readCounter, s.loadOrCreateCounter("inbound>>>"+inbound+">>>traffic>>>uplink"))
		writeCounter = append(writeCounter, s.loadOrCreateCounter("inbound>>>"+inbound+">>>traffic>>>downlink"))
	}
	if outbound != "" {
		readCounter = append(readCounter, s.loadOrCreateCounter("outbound>>>"+outbound+">>>traffic>>>uplink"))
		writeCounter = append(writeCounter, s.loadOrCreateCounter("outbound>>>"+outbound+">>>traffic>>>downlink"))
	}
	if user != "" {
		readCounter = append(readCounter, s.loadOrCreateCounter("user>>>"+user+">>>traffic>>>uplink"))
		writeCounter = append(writeCounter, s.loadOrCreateCounter("user>>>"+user+">>>traffic>>>downlink"))
	}
	s.access.Unlock()

	// Increment connections counter
	s.connectionsTotal.Inc()
	s.activeConnections.With(prometheus.Labels{
		"inbound":  inbound,
		"outbound": outbound,
	}).Inc()

	// Wrap connection to track when it closes
	return &trackedConn{
		Conn:         bufio.NewInt64CounterConn(conn, readCounter, writeCounter),
		service:      s,
		inbound:      inbound,
		outbound:     outbound,
		remoteAddr:   metadata.Destination,
		localAddr:    M.SocksaddrFromNet(conn.LocalAddr()),
	}
}

func (s *Service) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	if s == nil {
		return conn
	}

	inbound := metadata.Inbound
	user := metadata.User
	outbound := matchOutbound.Tag()

	var readCounter []*atomic.Int64
	var writeCounter []*atomic.Int64

	s.access.Lock()
	if inbound != "" {
		readCounter = append(readCounter, s.loadOrCreateCounter("inbound>>>"+inbound+">>>traffic>>>uplink"))
		writeCounter = append(writeCounter, s.loadOrCreateCounter("inbound>>>"+inbound+">>>traffic>>>downlink"))
	}
	if outbound != "" {
		readCounter = append(readCounter, s.loadOrCreateCounter("outbound>>>"+outbound+">>>traffic>>>uplink"))
		writeCounter = append(writeCounter, s.loadOrCreateCounter("outbound>>>"+outbound+">>>traffic>>>downlink"))
	}
	if user != "" {
		readCounter = append(readCounter, s.loadOrCreateCounter("user>>>"+user+">>>traffic>>>uplink"))
		writeCounter = append(writeCounter, s.loadOrCreateCounter("user>>>"+user+">>>traffic>>>downlink"))
	}
	s.access.Unlock()

	// Increment connections counter
	s.connectionsTotal.Inc()
	s.activeConnections.With(prometheus.Labels{
		"inbound":  inbound,
		"outbound": outbound,
	}).Inc()

	// Wrap packet connection to track when it closes
	return &trackedPacketConn{
		PacketConn: bufio.NewInt64CounterPacketConn(conn, readCounter, nil, writeCounter, nil),
		service:    s,
		inbound:    inbound,
		outbound:   outbound,
	}
}

func (s *Service) loadOrCreateCounter(name string) *atomic.Int64 {
	counter, loaded := s.counters[name]
	if loaded {
		return counter
	}
	counter = &atomic.Int64{}
	s.counters[name] = counter
	return counter
}

// trackedConn wraps a connection to decrement active connections on close
type trackedConn struct {
	net.Conn
	service    *Service
	inbound    string
	outbound   string
	remoteAddr M.Socksaddr
	localAddr  M.Socksaddr
	closeOnce  sync.Once
}

func (c *trackedConn) Close() error {
	c.closeOnce.Do(func() {
		c.service.activeConnections.With(prometheus.Labels{
			"inbound":  c.inbound,
			"outbound": c.outbound,
		}).Dec()
	})
	return c.Conn.Close()
}

// trackedPacketConn wraps a packet connection to decrement active connections on close
type trackedPacketConn struct {
	N.PacketConn
	service   *Service
	inbound   string
	outbound  string
	closeOnce sync.Once
}

func (c *trackedPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.service.activeConnections.With(prometheus.Labels{
			"inbound":  c.inbound,
			"outbound": c.outbound,
		}).Dec()
	})
	return c.PacketConn.Close()
}

// RecordDNSQuery records a DNS query in metrics
func (s *Service) RecordDNSQuery(transport string, domain string, qType string, status string) {
	if s == nil {
		return
	}
	s.dnsQueries.With(prometheus.Labels{
		"transport": transport,
		"domain":    domain,
		"type":      qType,
		"status":    status,
	}).Inc()
}
