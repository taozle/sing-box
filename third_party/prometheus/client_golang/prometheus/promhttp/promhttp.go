package promhttp

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type HandlerOpts struct{}

func HandlerFor(registry *prometheus.Registry, _ HandlerOpts) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		if r.Method == http.MethodHead {
			return
		}
		families := registry.Gather()
		sort.Slice(families, func(i, j int) bool {
			return families[i].Name < families[j].Name
		})
		for _, family := range families {
			writeFamily(w, family)
		}
	})
}

func writeFamily(w io.Writer, family *prometheus.MetricFamily) {
	if family == nil {
		return
	}
	fmt.Fprintf(w, "# HELP %s %s\n", family.Name, escapeString(family.Help))
	fmt.Fprintf(w, "# TYPE %s %s\n", family.Name, string(family.Type))
	for _, sample := range family.Samples {
		writeSample(w, family, sample)
	}
}

func writeSample(w io.Writer, family *prometheus.MetricFamily, sample prometheus.Sample) {
	switch family.Type {
	case prometheus.MetricTypeCounter, prometheus.MetricTypeGauge:
		fmt.Fprintf(w, "%s%s %g\n", family.Name, formatLabels(sample.Labels), sample.Value)
	case prometheus.MetricTypeHistogram:
		for _, bucket := range sample.Buckets {
			fmt.Fprintf(w, "%s_bucket%s %d\n", family.Name, formatLabels(withLE(sample.Labels, bucket.UpperBound)), bucket.Count)
		}
		fmt.Fprintf(w, "%s_sum%s %g\n", family.Name, formatLabels(sample.Labels), sample.Sum)
		fmt.Fprintf(w, "%s_count%s %d\n", family.Name, formatLabels(sample.Labels), sample.Count)
	}
}

func withLE(labels []prometheus.Label, bound float64) []prometheus.Label {
	le := "+Inf"
	if !math.IsInf(bound, 1) {
		le = strconv.FormatFloat(bound, 'f', -1, 64)
	}
	combined := make([]prometheus.Label, len(labels)+1)
	copy(combined, labels)
	combined[len(labels)] = prometheus.Label{Name: "le", Value: le}
	return combined
}

func formatLabels(labels []prometheus.Label) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, len(labels))
	for i, label := range labels {
		parts[i] = fmt.Sprintf("%s=\"%s\"", label.Name, escapeLabelValue(label.Value))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func escapeLabelValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}

func escapeString(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return value
}
