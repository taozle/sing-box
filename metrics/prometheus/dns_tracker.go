package prometheus

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
)

type dnsTracker struct {
	metrics *dnsMetricsSet
}

func newDNSTracker(metrics *dnsMetricsSet) *dnsTracker {
	return &dnsTracker{metrics: metrics}
}

func (t *dnsTracker) ObserveDNSQuery(_ context.Context, observation adapter.DNSQueryObservation) {
	t.metrics.observe(observation)
}
