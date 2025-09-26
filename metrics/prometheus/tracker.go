package prometheus

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

type metricsTracker struct {
	metrics *metricsSet
}

func newTracker(metrics *metricsSet) *metricsTracker {
	return &metricsTracker{metrics: metrics}
}

func (t *metricsTracker) RoutedConnection(_ context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	labels := t.connectionLabels(metadata, matchedRule, matchOutbound)
	return t.wrapConnection(conn, labels)
}

func (t *metricsTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	labels := t.connectionLabels(metadata, matchedRule, matchOutbound)
	return t.wrapPacketConnection(conn, labels)
}

func (t *metricsTracker) connectionLabels(metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) []string {
	network := metadata.Network
	if network == "" {
		network = labelValueUnknown
	}

	inbound := metadata.Inbound
	if inbound == "" {
		if metadata.InboundType != "" {
			inbound = metadata.InboundType
		} else {
			inbound = labelValueDefault
		}
	}

	inboundType := metadata.InboundType
	if inboundType == "" {
		inboundType = labelValueUnknown
	}

	outboundTag := labelValueNone
	outboundType := labelValueUnknown
	if matchOutbound != nil {
		outboundTag = matchOutbound.Tag()
		if outboundTag == "" {
			outboundTag = labelValueDefault
		}
		outboundType = matchOutbound.Type()
		if outboundType == "" {
			outboundType = labelValueUnknown
		}
	}

	ruleType := labelValueNone
	if matchedRule != nil {
		ruleType = matchedRule.Type()
		if ruleType == "" {
			ruleType = labelValueUnknown
		}
	}

	return []string{network, inbound, inboundType, outboundTag, outboundType, ruleType}
}

func (t *metricsTracker) wrapConnection(conn net.Conn, labels []string) net.Conn {
	t.metrics.observeConnectionStart(labels)

	uplinkLabels := make([]string, len(labels)+1)
	uplinkLabels[0] = directionUplink
	copy(uplinkLabels[1:], labels)

	downlinkLabels := make([]string, len(labels)+1)
	downlinkLabels[0] = directionDownlink
	copy(downlinkLabels[1:], labels)

	counterConn := bufio.NewCounterConn(conn, []N.CountFunc{
		func(n int64) { t.metrics.observeTraffic(uplinkLabels, n) },
	}, []N.CountFunc{
		func(n int64) { t.metrics.observeTraffic(downlinkLabels, n) },
	})

	return &trackedConn{
		ExtendedConn: counterConn,
		metrics:      t.metrics,
		labels:       labels,
		start:        time.Now(),
	}
}

func (t *metricsTracker) wrapPacketConnection(conn N.PacketConn, labels []string) N.PacketConn {
	t.metrics.observeConnectionStart(labels)

	uplinkLabels := make([]string, len(labels)+1)
	uplinkLabels[0] = directionUplink
	copy(uplinkLabels[1:], labels)

	downlinkLabels := make([]string, len(labels)+1)
	downlinkLabels[0] = directionDownlink
	copy(downlinkLabels[1:], labels)

	counterConn := bufio.NewCounterPacketConn(conn, []N.CountFunc{
		func(n int64) { t.metrics.observeTraffic(uplinkLabels, n) },
	}, []N.CountFunc{
		func(n int64) { t.metrics.observeTraffic(downlinkLabels, n) },
	})

	return &trackedPacketConn{
		PacketConn: counterConn,
		metrics:    t.metrics,
		labels:     labels,
		start:      time.Now(),
	}
}

type trackedConn struct {
	N.ExtendedConn
	metrics   *metricsSet
	labels    []string
	start     time.Time
	closeOnce sync.Once
	closeErr  error
}

func (c *trackedConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.ExtendedConn.Close()
		c.metrics.observeConnectionClose(c.labels, time.Since(c.start))
	})
	return c.closeErr
}

func (c *trackedConn) Upstream() any {
	return c.ExtendedConn
}

type trackedPacketConn struct {
	N.PacketConn
	metrics   *metricsSet
	labels    []string
	start     time.Time
	closeOnce sync.Once
	closeErr  error
}

func (c *trackedPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.PacketConn.Close()
		c.metrics.observeConnectionClose(c.labels, time.Since(c.start))
	})
	return c.closeErr
}

func (c *trackedPacketConn) Upstream() any {
	return c.PacketConn
}
