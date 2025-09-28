package prometheus

import (
	"net/http"

	promlib "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type Exporter struct {
	logger     log.ContextLogger
	options    option.PrometheusOptions
	registry   *promlib.Registry
	handler    http.Handler
	tracker    *metricsTracker
	dnsTracker *dnsTracker
	httpServer *http.Server
}

func NewExporter(logger log.ContextLogger, options option.PrometheusOptions) (*Exporter, error) {
	registry := promlib.NewRegistry()
	metrics := newMetricsSet(registry)
	dnsMetrics := newDNSMetricsSet(registry)
	exporter := &Exporter{
		logger:     logger,
		options:    options,
		registry:   registry,
		handler:    promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
		tracker:    newTracker(metrics),
		dnsTracker: newDNSTracker(dnsMetrics),
	}
	return exporter, nil
}

func (e *Exporter) ConnectionTracker() adapter.ConnectionTracker {
	return e.tracker
}

func (e *Exporter) DNSTracker() adapter.DNSTracker {
	return e.dnsTracker
}

func (e *Exporter) Start() error {
	if e.options.Listen == "" {
		return nil
	}
	path := e.options.Path
	if path == "" {
		path = "/metrics"
	}
	mux := http.NewServeMux()
	mux.Handle(path, e.handler)
	e.httpServer = &http.Server{
		Addr:    e.options.Listen,
		Handler: mux,
	}
	go func() {
		err := e.httpServer.ListenAndServe()
		if err != nil && !E.IsClosed(err) {
			e.logger.Error("serve prometheus metrics: ", err)
		}
	}()
	e.logger.Info("prometheus metrics exporter listening on ", e.options.Listen, " path ", path)
	return nil
}

func (e *Exporter) Close() error {
	if e.httpServer == nil {
		return nil
	}
	return e.httpServer.Close()
}
