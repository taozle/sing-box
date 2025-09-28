package option

type PrometheusOptions struct {
	Listen string `json:"listen,omitempty"`
	Path   string `json:"path,omitempty"`
}
