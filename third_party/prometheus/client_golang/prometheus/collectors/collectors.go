package collectors

import "github.com/prometheus/client_golang/prometheus"

type ProcessCollectorOpts struct{}

type noopCollector struct{}

func (noopCollector) Collect() []*prometheus.MetricFamily {
	return nil
}

func NewProcessCollector(ProcessCollectorOpts) prometheus.Collector {
	return noopCollector{}
}

func NewGoCollector() prometheus.Collector {
	return noopCollector{}
}
