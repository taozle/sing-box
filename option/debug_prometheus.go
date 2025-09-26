package option

// PrometheusOptions configures the optional Prometheus metrics exporter that
// is exposed from the debug HTTP server.
type PrometheusOptions struct {
	// Listen specifies the TCP address used by the exporter HTTP server.
	// If empty, "127.0.0.1:9090" is used.
	Listen string `json:"listen,omitempty"`
	// Path configures the HTTP path for the metrics endpoint. If empty the
	// exporter serves metrics at "/metrics".
	Path string `json:"path,omitempty"`
	// DisableProcessCollector disables the process collector from the
	// Prometheus Go client library.
	DisableProcessCollector bool `json:"disable_process_collector,omitempty"`
	// DisableGoCollector disables the Go runtime collector from the
	// Prometheus Go client library.
	DisableGoCollector bool `json:"disable_go_collector,omitempty"`
}
