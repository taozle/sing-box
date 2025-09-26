package prometheus

import (
	"context"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/sagernet/sing-box/adapter"
)

type dnsTracker struct {
	metrics *dnsMetricsSet
}

func newDNSTracker(metrics *dnsMetricsSet) *dnsTracker {
	return &dnsTracker{metrics: metrics}
}

func (t *dnsTracker) ObserveDNSQuery(_ context.Context, observation adapter.DNSQueryObservation) {
	if t.metrics == nil {
		return
	}

	serverLabel := labelValueUnknown
	serverTypeLabel := labelValueUnknown
	if observation.Transport != nil {
		serverLabel = observation.Transport.Tag()
		if serverLabel == "" {
			serverLabel = labelValueDefault
		}
		serverTypeLabel = observation.Transport.Type()
		if serverTypeLabel == "" {
			serverTypeLabel = labelValueUnknown
		}
	} else if observation.Cached {
		serverLabel = labelValueCache
		serverTypeLabel = labelValueCache
	} else {
		serverLabel = labelValueNone
		serverTypeLabel = labelValueNone
	}

	ruleLabel := labelValueNone
	if observation.Rule != nil {
		ruleLabel = observation.Rule.Type()
		if ruleLabel == "" {
			ruleLabel = labelValueUnknown
		}
	}

	cacheLabel := cacheLabelMiss
	if observation.Cached {
		cacheLabel = cacheLabelHit
	}

	rcodeLabel := labelValueUnknown
	if observation.Err != nil && observation.RCode < 0 {
		rcodeLabel = labelValueError
	} else if observation.RCode >= 0 {
		rcodeLabel = strings.ToLower(dns.RcodeToString[observation.RCode])
		if rcodeLabel == "" {
			rcodeLabel = strconv.Itoa(observation.RCode)
		}
	}

	qtypeLabel := strings.ToLower(dns.TypeToString[observation.Question.Qtype])
	if qtypeLabel == "" {
		qtypeLabel = strconv.Itoa(int(observation.Question.Qtype))
	}

	var domain string
	if observation.Metadata != nil {
		domain = observation.Metadata.Domain
	}
	if domain == "" {
		domain = strings.TrimSuffix(observation.Question.Name, ".")
	}
	domain = strings.ToLower(domain)

	t.metrics.observe(cacheLabel, serverLabel, serverTypeLabel, ruleLabel, rcodeLabel, qtypeLabel, domain, observation.Duration, observation.Cached)
}

var _ adapter.DNSTracker = (*dnsTracker)(nil)
