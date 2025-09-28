package prometheus

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Labels map[string]string

type metricType string

const (
	metricTypeCounter   metricType = "counter"
	metricTypeGauge     metricType = "gauge"
	metricTypeHistogram metricType = "histogram"
)

type ValueType metricType

const (
	CounterValue   ValueType = ValueType(metricTypeCounter)
	GaugeValue     ValueType = ValueType(metricTypeGauge)
	HistogramValue ValueType = ValueType(metricTypeHistogram)
)

type Desc struct {
	fqName           string
	help             string
	variableLabels   []string
	constLabelNames  []string
	constLabelValues []string
	metricType       metricType
}

type Collector interface {
	Describe(chan<- *Desc)
	Collect(chan<- Metric)
}

type Metric interface {
	appendTo(map[string]*metricFamily)
	Desc() *Desc
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
	defer r.mu.Unlock()
	r.collectors = append(r.collectors, collectors...)
}

type CounterOpts struct {
	Namespace   string
	Subsystem   string
	Name        string
	Help        string
	ConstLabels Labels
}

type GaugeOpts struct {
	Namespace   string
	Subsystem   string
	Name        string
	Help        string
	ConstLabels Labels
}

type HistogramOpts struct {
	Namespace   string
	Subsystem   string
	Name        string
	Help        string
	ConstLabels Labels
	Buckets     []float64
}

func buildFQName(namespace, subsystem, name string) string {
	var parts []string
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

func newDesc(namespace, subsystem, name, help string, constLabels Labels, labelNames []string, mType metricType) *Desc {
	desc := &Desc{
		fqName:         buildFQName(namespace, subsystem, name),
		help:           help,
		variableLabels: append([]string(nil), labelNames...),
		metricType:     mType,
	}
	if len(constLabels) > 0 {
		desc.constLabelNames = make([]string, 0, len(constLabels))
		for k := range constLabels {
			desc.constLabelNames = append(desc.constLabelNames, k)
		}
		sort.Strings(desc.constLabelNames)
		desc.constLabelValues = make([]string, len(desc.constLabelNames))
		for i, name := range desc.constLabelNames {
			desc.constLabelValues[i] = constLabels[name]
		}
	}
	return desc
}

// CounterVec

type CounterVec struct {
	desc    *Desc
	mu      sync.RWMutex
	metrics map[string]*counter
}

type counter struct {
	mu          sync.Mutex
	value       float64
	labelValues []string
}

type CounterMetric struct {
	vec   *CounterVec
	entry *counter
}

func NewCounterVec(opts CounterOpts, labelNames []string) *CounterVec {
	return &CounterVec{
		desc:    newDesc(opts.Namespace, opts.Subsystem, opts.Name, opts.Help, opts.ConstLabels, labelNames, metricTypeCounter),
		metrics: make(map[string]*counter),
	}
}

func (v *CounterVec) WithLabelValues(labelValues ...string) CounterMetric {
	if len(labelValues) != len(v.desc.variableLabels) {
		panic("prometheus: inconsistent label cardinality")
	}
	key := labelKey(labelValues)
	v.mu.RLock()
	entry, ok := v.metrics[key]
	v.mu.RUnlock()
	if !ok {
		v.mu.Lock()
		entry, ok = v.metrics[key]
		if !ok {
			entry = &counter{labelValues: append([]string(nil), labelValues...)}
			v.metrics[key] = entry
		}
		v.mu.Unlock()
	}
	return CounterMetric{vec: v, entry: entry}
}

func (v *CounterVec) With(labels Labels) CounterMetric {
	return v.WithLabelValues(labelValuesFrom(labels, v.desc.variableLabels)...)
}

func (m CounterMetric) Inc() {
	m.Add(1)
}

func (m CounterMetric) Add(value float64) {
	if value < 0 {
		panic("prometheus: counter cannot add negative value")
	}
	m.entry.mu.Lock()
	m.entry.value += value
	m.entry.mu.Unlock()
}

func (v *CounterVec) Describe(ch chan<- *Desc) {
	ch <- v.desc
}

func (v *CounterVec) Collect(ch chan<- Metric) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, entry := range v.metrics {
		entry.mu.Lock()
		sample := &counterSample{
			desc:        v.desc,
			labelValues: append([]string(nil), entry.labelValues...),
			value:       entry.value,
		}
		entry.mu.Unlock()
		ch <- sample
	}
}

// GaugeVec

type GaugeVec struct {
	desc    *Desc
	mu      sync.RWMutex
	metrics map[string]*gauge
}

type gauge struct {
	mu          sync.Mutex
	value       float64
	labelValues []string
}

type GaugeMetric struct {
	vec   *GaugeVec
	entry *gauge
}

func NewGaugeVec(opts GaugeOpts, labelNames []string) *GaugeVec {
	return &GaugeVec{
		desc:    newDesc(opts.Namespace, opts.Subsystem, opts.Name, opts.Help, opts.ConstLabels, labelNames, metricTypeGauge),
		metrics: make(map[string]*gauge),
	}
}

func (v *GaugeVec) WithLabelValues(labelValues ...string) GaugeMetric {
	if len(labelValues) != len(v.desc.variableLabels) {
		panic("prometheus: inconsistent label cardinality")
	}
	key := labelKey(labelValues)
	v.mu.RLock()
	entry, ok := v.metrics[key]
	v.mu.RUnlock()
	if !ok {
		v.mu.Lock()
		entry, ok = v.metrics[key]
		if !ok {
			entry = &gauge{labelValues: append([]string(nil), labelValues...)}
			v.metrics[key] = entry
		}
		v.mu.Unlock()
	}
	return GaugeMetric{vec: v, entry: entry}
}

func (v *GaugeVec) With(labels Labels) GaugeMetric {
	return v.WithLabelValues(labelValuesFrom(labels, v.desc.variableLabels)...)
}

func (v *GaugeVec) DeleteLabelValues(labelValues ...string) {
	if len(labelValues) != len(v.desc.variableLabels) {
		return
	}
	key := labelKey(labelValues)
	v.mu.Lock()
	delete(v.metrics, key)
	v.mu.Unlock()
}

func (m GaugeMetric) Set(value float64) {
	m.entry.mu.Lock()
	m.entry.value = value
	m.entry.mu.Unlock()
}

func (m GaugeMetric) Add(value float64) {
	m.entry.mu.Lock()
	m.entry.value += value
	m.entry.mu.Unlock()
}

func (m GaugeMetric) Inc() {
	m.Add(1)
}

func (m GaugeMetric) Dec() {
	m.Add(-1)
}

func (v *GaugeVec) Describe(ch chan<- *Desc) {
	ch <- v.desc
}

func (v *GaugeVec) Collect(ch chan<- Metric) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, entry := range v.metrics {
		entry.mu.Lock()
		sample := &gaugeSample{
			desc:        v.desc,
			labelValues: append([]string(nil), entry.labelValues...),
			value:       entry.value,
		}
		entry.mu.Unlock()
		ch <- sample
	}
}

// HistogramVec

type HistogramVec struct {
	desc    *Desc
	buckets []float64
	mu      sync.RWMutex
	metrics map[string]*histogram
}

type histogram struct {
	mu          sync.Mutex
	counts      []uint64
	sum         float64
	count       uint64
	labelValues []string
}

type HistogramMetric struct {
	vec   *HistogramVec
	entry *histogram
}

var defaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

func NewHistogramVec(opts HistogramOpts, labelNames []string) *HistogramVec {
	buckets := opts.Buckets
	if len(buckets) == 0 {
		buckets = defaultBuckets
	} else {
		sorted := append([]float64(nil), buckets...)
		sort.Float64s(sorted)
		buckets = sorted
	}
	return &HistogramVec{
		desc:    newDesc(opts.Namespace, opts.Subsystem, opts.Name, opts.Help, opts.ConstLabels, labelNames, metricTypeHistogram),
		buckets: buckets,
		metrics: make(map[string]*histogram),
	}
}

func (v *HistogramVec) WithLabelValues(labelValues ...string) HistogramMetric {
	if len(labelValues) != len(v.desc.variableLabels) {
		panic("prometheus: inconsistent label cardinality")
	}
	key := labelKey(labelValues)
	v.mu.RLock()
	entry, ok := v.metrics[key]
	v.mu.RUnlock()
	if !ok {
		v.mu.Lock()
		entry, ok = v.metrics[key]
		if !ok {
			entry = &histogram{
				counts:      make([]uint64, len(v.buckets)),
				labelValues: append([]string(nil), labelValues...),
			}
			v.metrics[key] = entry
		}
		v.mu.Unlock()
	}
	return HistogramMetric{vec: v, entry: entry}
}

func (v *HistogramVec) With(labels Labels) HistogramMetric {
	return v.WithLabelValues(labelValuesFrom(labels, v.desc.variableLabels)...)
}

func (m HistogramMetric) Observe(value float64) {
	m.entry.mu.Lock()
	defer m.entry.mu.Unlock()
	idx := sort.SearchFloat64s(m.vec.buckets, value)
	if idx < len(m.vec.buckets) {
		m.entry.counts[idx]++
	}
	m.entry.sum += value
	m.entry.count++
}

func (v *HistogramVec) Describe(ch chan<- *Desc) {
	ch <- v.desc
}

func (v *HistogramVec) Collect(ch chan<- Metric) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, entry := range v.metrics {
		entry.mu.Lock()
		sample := &histogramSampleMetric{
			desc:        v.desc,
			labelValues: append([]string(nil), entry.labelValues...),
			buckets:     append([]float64(nil), v.buckets...),
			counts:      append([]uint64(nil), entry.counts...),
			sum:         entry.sum,
			count:       entry.count,
		}
		entry.mu.Unlock()
		ch <- sample
	}
}

// metric samples

type counterSample struct {
	desc        *Desc
	labelValues []string
	value       float64
}

type gaugeSample struct {
	desc        *Desc
	labelValues []string
	value       float64
}

type histogramSampleMetric struct {
	desc        *Desc
	labelValues []string
	buckets     []float64
	counts      []uint64
	sum         float64
	count       uint64
}

type labelPair struct {
	name  string
	value string
}

type metricFamily struct {
	desc       *Desc
	samples    []sample
	histograms []histogramSample
}

type sample struct {
	labels []labelPair
	value  float64
}

type histogramSample struct {
	labels  []labelPair
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
}

func (s *counterSample) appendTo(families map[string]*metricFamily) {
	family := ensureFamily(families, s.desc)
	family.samples = append(family.samples, sample{labels: buildLabelPairs(s.desc, s.labelValues), value: s.value})
}

func (s *counterSample) Desc() *Desc { return s.desc }

func (s *gaugeSample) appendTo(families map[string]*metricFamily) {
	family := ensureFamily(families, s.desc)
	family.samples = append(family.samples, sample{labels: buildLabelPairs(s.desc, s.labelValues), value: s.value})
}

func (s *gaugeSample) Desc() *Desc { return s.desc }

func (s *histogramSampleMetric) appendTo(families map[string]*metricFamily) {
	family := ensureFamily(families, s.desc)
	family.histograms = append(family.histograms, histogramSample{
		labels:  buildLabelPairs(s.desc, s.labelValues),
		buckets: s.buckets,
		counts:  s.counts,
		sum:     s.sum,
		count:   s.count,
	})
}

func (s *histogramSampleMetric) Desc() *Desc { return s.desc }

func ensureFamily(families map[string]*metricFamily, desc *Desc) *metricFamily {
	if family, ok := families[desc.fqName]; ok {
		return family
	}
	family := &metricFamily{desc: desc}
	families[desc.fqName] = family
	return family
}

func buildLabelPairs(desc *Desc, values []string) []labelPair {
	total := len(desc.constLabelNames) + len(desc.variableLabels)
	if total == 0 {
		return nil
	}
	labels := make([]labelPair, 0, total)
	for i, name := range desc.constLabelNames {
		labels = append(labels, labelPair{name: name, value: desc.constLabelValues[i]})
	}
	for i, name := range desc.variableLabels {
		labels = append(labels, labelPair{name: name, value: values[i]})
	}
	return labels
}

func labelKey(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, "\xff")
}

func labelValuesFrom(labels Labels, keys []string) []string {
	values := make([]string, len(keys))
	for i, key := range keys {
		values[i] = labels[key]
	}
	return values
}

func (r *Registry) gather() []*metricFamily {
	r.mu.RLock()
	collectors := append([]Collector(nil), r.collectors...)
	r.mu.RUnlock()
	families := make(map[string]*metricFamily)
	for _, collector := range collectors {
		ch := make(chan Metric, 16)
		go func(c Collector) {
			c.Collect(ch)
			close(ch)
		}(collector)
		for metric := range ch {
			metric.appendTo(families)
		}
	}
	result := make([]*metricFamily, 0, len(families))
	for _, family := range families {
		sort.SliceStable(family.samples, func(i, j int) bool {
			return compareLabels(family.samples[i].labels, family.samples[j].labels)
		})
		sort.SliceStable(family.histograms, func(i, j int) bool {
			return compareLabels(family.histograms[i].labels, family.histograms[j].labels)
		})
		result = append(result, family)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].desc.fqName < result[j].desc.fqName
	})
	return result
}

func compareLabels(a, b []labelPair) bool {
	max := len(a)
	if len(b) < max {
		max = len(b)
	}
	for i := 0; i < max; i++ {
		if a[i].name != b[i].name {
			return a[i].name < b[i].name
		}
		if a[i].value != b[i].value {
			return a[i].value < b[i].value
		}
	}
	return len(a) < len(b)
}

func escapeString(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return value
}

func formatLabelPairs(pairs []labelPair) string {
	if len(pairs) == 0 {
		return ""
	}
	builder := strings.Builder{}
	builder.WriteByte('{')
	for i, pair := range pairs {
		if i > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(pair.name)
		builder.WriteByte('=')
		builder.WriteByte('"')
		builder.WriteString(escapeString(pair.value))
		builder.WriteByte('"')
	}
	builder.WriteByte('}')
	return builder.String()
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}

func appendLabel(pairs []labelPair, name, value string) []labelPair {
	out := make([]labelPair, len(pairs)+1)
	copy(out, pairs)
	out[len(pairs)] = labelPair{name: name, value: value}
	return out
}

func (r *Registry) WriteTo(writer io.Writer) error {
	families := r.gather()
	for _, family := range families {
		if _, err := fmt.Fprintf(writer, "# HELP %s %s\n", family.desc.fqName, escapeString(family.desc.help)); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "# TYPE %s %s\n", family.desc.fqName, family.desc.metricType); err != nil {
			return err
		}
		switch family.desc.metricType {
		case metricTypeHistogram:
			for _, hist := range family.histograms {
				cumulative := uint64(0)
				for i, upper := range hist.buckets {
					cumulative += hist.counts[i]
					labels := appendLabel(hist.labels, "le", formatFloat(upper))
					if _, err := fmt.Fprintf(writer, "%s_bucket%s %d\n", family.desc.fqName, formatLabelPairs(labels), cumulative); err != nil {
						return err
					}
				}
				labels := appendLabel(hist.labels, "le", "+Inf")
				if _, err := fmt.Fprintf(writer, "%s_bucket%s %d\n", family.desc.fqName, formatLabelPairs(labels), hist.count); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(writer, "%s_sum%s %s\n", family.desc.fqName, formatLabelPairs(hist.labels), formatFloat(hist.sum)); err != nil {
					return err
				}
				if _, err := fmt.Fprintf(writer, "%s_count%s %d\n", family.desc.fqName, formatLabelPairs(hist.labels), hist.count); err != nil {
					return err
				}
			}
		default:
			for _, sample := range family.samples {
				if _, err := fmt.Fprintf(writer, "%s%s %s\n", family.desc.fqName, formatLabelPairs(sample.labels), formatFloat(sample.value)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
