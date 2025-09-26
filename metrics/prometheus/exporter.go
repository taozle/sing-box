package prometheus

import (
	"errors"
	"net"
	"net/http"
	"runtime"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	defaultListenAddr  = "127.0.0.1:9090"
	defaultMetricsPath = "/metrics"
)

type Exporter struct {
	logger   log.ContextLogger
	options  option.PrometheusOptions
	registry *prometheus.Registry
	server   *http.Server
	listener net.Listener
}

func NewExporter(logger log.ContextLogger, router adapter.Router, dnsRouter adapter.DNSRouter, options option.PrometheusOptions) (*Exporter, error) {
	listen := strings.TrimSpace(options.Listen)
	if listen == "" {
		listen = defaultListenAddr
	}
	path := strings.TrimSpace(options.Path)
	if path == "" {
		path = defaultMetricsPath
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	registry := prometheus.NewRegistry()
	if !options.DisableProcessCollector {
		registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}
	if !options.DisableGoCollector {
		registry.MustRegister(collectors.NewGoCollector())
	}

	connectionMetrics := newMetricsSet(registry)
	dnsMetrics := newDNSMetricsSet(registry)

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "sing_box",
		Name:      "build_info",
		Help:      "Build information about the running sing-box instance.",
	}, []string{"version", "go_version"})
	buildInfo.WithLabelValues(C.Version, runtime.Version()).Set(1)
	registry.MustRegister(buildInfo)

	tracker := newTracker(connectionMetrics)
	if router == nil {
		return nil, E.New("missing router in context")
	}
	router.AppendTracker(tracker)

	if dnsRouter == nil {
		return nil, E.New("missing DNS router in context")
	}
	dnsRouter.AppendDNSTracker(newDNSTracker(dnsMetrics))

	mux := http.NewServeMux()
	mux.Handle(path, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	exporter := &Exporter{
		logger:   logger,
		options:  option.PrometheusOptions{Listen: listen, Path: path, DisableProcessCollector: options.DisableProcessCollector, DisableGoCollector: options.DisableGoCollector},
		registry: registry,
		server: &http.Server{
			Addr:    listen,
			Handler: mux,
		},
	}
	return exporter, nil
}

func (e *Exporter) Start() error {
	if e.server == nil {
		return nil
	}
	listener, err := net.Listen("tcp", e.options.Listen)
	if err != nil {
		return err
	}
	e.listener = listener
	go func() {
		if err := e.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			e.logger.Error("serve prometheus metrics: ", err)
		}
	}()
	e.logger.Info("prometheus metrics exporter listening on ", e.options.Listen, " path ", e.options.Path)
	return nil
}

func (e *Exporter) Close() error {
	return common.Close(
		common.Closer(func() error {
			if e.server == nil {
				return nil
			}
			err := e.server.Close()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		}),
		common.Closer(func() error {
			if e.listener == nil {
				return nil
			}
			return e.listener.Close()
		}),
	)
}

func (e *Exporter) Upstream() any {
	return e.registry
}
