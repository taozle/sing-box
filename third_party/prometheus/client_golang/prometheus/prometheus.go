package prometheus

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
)

type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
)

type Label struct {
	Name  string
	Value string
}

type Bucket struct {
	UpperBound float64
	Count      uint64
}

type Sample struct {
	Labels  []Label
	Value   float64
	Buckets []Bucket
	Sum     float64
	Count   uint64
}

type MetricFamily struct {
	Name    string
	Help    string
	Type    MetricType
	Samples []Sample
}

type Collector interface {
	Collect() []*MetricFamily
}

type Registry struct {
	mu         sync.RWMutex
	collectors []Collector
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) MustRegister(collectors ...Collector) {
	r.mu.Lock()
	r.collectors = append(r.collectors, collectors...)
	r.mu.Unlock()
}

func (r *Registry) Gather() []*MetricFamily {
	r.mu.RLock()
	collectors := append([]Collector{}, r.collectors...)
	r.mu.RUnlock()
	var families []*MetricFamily
	for _, collector := range collectors {
		families = append(families, collector.Collect()...)
	}
	return families
}

type GaugeOpts struct {
	Namespace string
	Subsystem string
	Name      string
	Help      string
}

type CounterOpts struct {
	Namespace string
	Subsystem string
	Name      string
	Help      string
}

type HistogramOpts struct {
	Namespace string
	Subsystem string
	Name      string
	Help      string
	Buckets   []float64
}

type GaugeVec struct {
	opts       GaugeOpts
	labelNames []string
	mu         sync.RWMutex
	gauges     map[string]*gaugeValue
}

type gaugeValue struct {
	mu    sync.Mutex
	value float64
}

type Gauge struct {
	value *gaugeValue
}

type CounterVec struct {
	opts       CounterOpts
	labelNames []string
	mu         sync.RWMutex
	counters   map[string]*counterValue
}

type counterValue struct {
	mu    sync.Mutex
	value float64
}

type Counter struct {
	value *counterValue
}

type HistogramVec struct {
	opts       HistogramOpts
	labelNames []string
	mu         sync.RWMutex
	histograms map[string]*histogramValue
	bounds     []float64
}

type histogramValue struct {
	mu      sync.Mutex
	counts  []uint64
	sum     float64
	samples uint64
}

type Histogram struct {
	value  *histogramValue
	bounds []float64
}

func NewGaugeVec(opts GaugeOpts, labelNames []string) *GaugeVec {
	return &GaugeVec{
		opts:       opts,
		labelNames: append([]string(nil), labelNames...),
		gauges:     make(map[string]*gaugeValue),
	}
}

func (g *GaugeVec) WithLabelValues(values ...string) *Gauge {
	if len(values) != len(g.labelNames) {
		panic(fmt.Sprintf("unexpected label count %d, want %d", len(values), len(g.labelNames)))
	}
	key := labelKey(values)
	g.mu.Lock()
	gv, ok := g.gauges[key]
	if !ok {
		gv = new(gaugeValue)
		g.gauges[key] = gv
	}
	g.mu.Unlock()
	return &Gauge{value: gv}
}

func (g *Gauge) Set(value float64) {
	g.value.mu.Lock()
	g.value.value = value
	g.value.mu.Unlock()
}

func (g *Gauge) Inc() {
	g.Add(1)
}

func (g *Gauge) Dec() {
	g.Add(-1)
}

func (g *Gauge) Add(delta float64) {
	g.value.mu.Lock()
	g.value.value += delta
	g.value.mu.Unlock()
}

func (g *GaugeVec) Collect() []*MetricFamily {
	g.mu.RLock()
	defer g.mu.RUnlock()
	samples := make([]Sample, 0, len(g.gauges))
	for key, value := range g.gauges {
		labels := decodeLabelValues(key, g.labelNames)
		value.mu.Lock()
		sample := Sample{Labels: labels, Value: value.value}
		value.mu.Unlock()
		samples = append(samples, sample)
	}
	sortSamples(samples)
	family := &MetricFamily{
		Name:    buildFQName(g.opts.Namespace, g.opts.Subsystem, g.opts.Name),
		Help:    g.opts.Help,
		Type:    MetricTypeGauge,
		Samples: samples,
	}
	return []*MetricFamily{family}
}

func NewCounterVec(opts CounterOpts, labelNames []string) *CounterVec {
	return &CounterVec{
		opts:       opts,
		labelNames: append([]string(nil), labelNames...),
		counters:   make(map[string]*counterValue),
	}
}

func (c *CounterVec) WithLabelValues(values ...string) *Counter {
	if len(values) != len(c.labelNames) {
		panic(fmt.Sprintf("unexpected label count %d, want %d", len(values), len(c.labelNames)))
	}
	key := labelKey(values)
	c.mu.Lock()
	cv, ok := c.counters[key]
	if !ok {
		cv = new(counterValue)
		c.counters[key] = cv
	}
	c.mu.Unlock()
	return &Counter{value: cv}
}

func (c *Counter) Add(delta float64) {
	if delta < 0 {
		return
	}
	c.value.mu.Lock()
	c.value.value += delta
	c.value.mu.Unlock()
}

func (c *CounterVec) Collect() []*MetricFamily {
	c.mu.RLock()
	defer c.mu.RUnlock()
	samples := make([]Sample, 0, len(c.counters))
	for key, value := range c.counters {
		labels := decodeLabelValues(key, c.labelNames)
		value.mu.Lock()
		sample := Sample{Labels: labels, Value: value.value}
		value.mu.Unlock()
		samples = append(samples, sample)
	}
	sortSamples(samples)
	family := &MetricFamily{
		Name:    buildFQName(c.opts.Namespace, c.opts.Subsystem, c.opts.Name),
		Help:    c.opts.Help,
		Type:    MetricTypeCounter,
		Samples: samples,
	}
	return []*MetricFamily{family}
}

func NewHistogramVec(opts HistogramOpts, labelNames []string) *HistogramVec {
	bounds := append([]float64(nil), opts.Buckets...)
	sort.Float64s(bounds)
	if len(bounds) == 0 {
		bounds = append(bounds, math.Inf(1))
	} else if !math.IsInf(bounds[len(bounds)-1], 1) {
		bounds = append(bounds, math.Inf(1))
	}
	return &HistogramVec{
		opts:       opts,
		labelNames: append([]string(nil), labelNames...),
		histograms: make(map[string]*histogramValue),
		bounds:     bounds,
	}
}

func (h *HistogramVec) WithLabelValues(values ...string) *Histogram {
	if len(values) != len(h.labelNames) {
		panic(fmt.Sprintf("unexpected label count %d, want %d", len(values), len(h.labelNames)))
	}
	key := labelKey(values)
	h.mu.Lock()
	hv, ok := h.histograms[key]
	if !ok {
		hv = &histogramValue{
			counts: make([]uint64, len(h.bounds)),
		}
		h.histograms[key] = hv
	}
	h.mu.Unlock()
	return &Histogram{value: hv, bounds: h.bounds}
}

func (h *Histogram) Observe(value float64) {
	h.value.mu.Lock()
	h.value.sum += value
	h.value.samples++
	for i, upper := range h.bounds {
		if value <= upper {
			h.value.counts[i]++
		}
	}
	h.value.mu.Unlock()
}

func (h *HistogramVec) Collect() []*MetricFamily {
	h.mu.RLock()
	defer h.mu.RUnlock()
	samples := make([]Sample, 0, len(h.histograms))
	for key, value := range h.histograms {
		labels := decodeLabelValues(key, h.labelNames)
		value.mu.Lock()
		buckets := make([]Bucket, len(h.bounds))
		for i, upper := range h.bounds {
			buckets[i] = Bucket{UpperBound: upper, Count: value.counts[i]}
		}
		sample := Sample{
			Labels:  labels,
			Buckets: buckets,
			Sum:     value.sum,
			Count:   value.samples,
		}
		value.mu.Unlock()
		samples = append(samples, sample)
	}
	sortSamples(samples)
	family := &MetricFamily{
		Name:    buildFQName(h.opts.Namespace, h.opts.Subsystem, h.opts.Name),
		Help:    h.opts.Help,
		Type:    MetricTypeHistogram,
		Samples: samples,
	}
	return []*MetricFamily{family}
}

func buildFQName(namespace, subsystem, name string) string {
	parts := make([]string, 0, 3)
	if namespace != "" {
		parts = append(parts, namespace)
	}
	if subsystem != "" {
		parts = append(parts, subsystem)
	}
	if name != "" {
		parts = append(parts, name)
	}
	return strings.Join(parts, "_")
}

func labelKey(values []string) string {
	return strings.Join(values, "\xff")
}

func decodeLabelValues(key string, labelNames []string) []Label {
	if len(labelNames) == 0 {
		return nil
	}
	values := strings.Split(key, "\xff")
	labels := make([]Label, len(labelNames))
	for i, name := range labelNames {
		labels[i] = Label{Name: name, Value: values[i]}
	}
	return labels
}

func sortSamples(samples []Sample) {
	sort.Slice(samples, func(i, j int) bool {
		if samples[i].Labels == nil && samples[j].Labels == nil {
			return false
		}
		if len(samples[i].Labels) != len(samples[j].Labels) {
			return len(samples[i].Labels) < len(samples[j].Labels)
		}
		for idx := range samples[i].Labels {
			if samples[i].Labels[idx].Name == samples[j].Labels[idx].Name {
				if samples[i].Labels[idx].Value == samples[j].Labels[idx].Value {
					continue
				}
				return samples[i].Labels[idx].Value < samples[j].Labels[idx].Value
			}
			return samples[i].Labels[idx].Name < samples[j].Labels[idx].Name
		}
		return false
	})
}

func init() {}
