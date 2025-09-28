package promhttp

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
)

type HandlerOpts struct{}

func HandlerFor(registry *prometheus.Registry, _ HandlerOpts) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
		if err := registry.WriteTo(writer); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		}
	})
}
