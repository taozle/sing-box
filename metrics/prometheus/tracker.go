package prometheus

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
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
	return newMetricsConn(conn, labels, t.metrics)
}

func (t *metricsTracker) RoutedPacketConnection(_ context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	labels := t.connectionLabels(metadata, matchedRule, matchOutbound)
	return newMetricsPacketConn(conn, labels, t.metrics)
}

func (t *metricsTracker) connectionLabels(metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) []string {
	inbound := normalize(metadata.Inbound)
	inboundType := normalize(metadata.InboundType)
	outbound := normalizeOutbound(metadata, matchOutbound)
	outboundType := normalizeOutboundType(matchOutbound)
	rule := "-"
	if matchedRule != nil {
		rule = normalize(matchedRule.Type())
	}
	network := normalize(metadata.Network)
	if network == "-" {
		network = normalize(metadata.Destination.Network())
	}
	return []string{inbound, inboundType, outbound, outboundType, rule, network}
}

func normalize(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func normalizeOutbound(metadata adapter.InboundContext, outbound adapter.Outbound) string {
	if outbound != nil {
		if tag := outbound.Tag(); tag != "" {
			return tag
		}
		return normalize(outbound.Type())
	}
	if metadata.Outbound != "" {
		return metadata.Outbound
	}
	return "-"
}

func normalizeOutboundType(outbound adapter.Outbound) string {
	if outbound == nil {
		return "-"
	}
	return normalize(outbound.Type())
}

type metricsConn struct {
	net.Conn
	metrics   *metricsSet
	labels    []string
	start     time.Time
	closeOnce sync.Once
}

func newMetricsConn(conn net.Conn, labels []string, metrics *metricsSet) net.Conn {
	wrapper := &metricsConn{
		Conn:    conn,
		metrics: metrics,
		labels:  append([]string(nil), labels...),
		start:   time.Now(),
	}
	metrics.observeConnectionStart(labels)
	return wrapper
}

func (c *metricsConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.metrics.observeTraffic(c.labels, "uplink", int64(n))
	}
	return n, err
}

func (c *metricsConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.metrics.observeTraffic(c.labels, "downlink", int64(n))
	}
	return n, err
}

func (c *metricsConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		c.metrics.observeConnectionClose(c.labels, time.Since(c.start))
	})
	return err
}

type metricsPacketConn struct {
	N.PacketConn
	metrics   *metricsSet
	labels    []string
	start     time.Time
	closeOnce sync.Once
}

func newMetricsPacketConn(conn N.PacketConn, labels []string, metrics *metricsSet) N.PacketConn {
	base := &metricsPacketConn{
		PacketConn: conn,
		metrics:    metrics,
		labels:     append([]string(nil), labels...),
		start:      time.Now(),
	}
	metrics.observeConnectionStart(labels)
	if netConn, ok := conn.(N.NetPacketConn); ok {
		return &metricsNetPacketConn{metricsPacketConn: base, netConn: netConn}
	}
	return base
}

func (c *metricsPacketConn) finish() {
	c.closeOnce.Do(func() {
		c.metrics.observeConnectionClose(c.labels, time.Since(c.start))
	})
}

func (c *metricsPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.finish()
	return err
}

func (c *metricsPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	destination, err = c.PacketConn.ReadPacket(buffer)
	if buffer != nil {
		c.metrics.observeTraffic(c.labels, "uplink", int64(buffer.Len()))
	}
	return
}

func (c *metricsPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if buffer != nil {
		c.metrics.observeTraffic(c.labels, "downlink", int64(buffer.Len()))
	}
	return c.PacketConn.WritePacket(buffer, destination)
}

type metricsNetPacketConn struct {
	*metricsPacketConn
	netConn N.NetPacketConn
}

func (c *metricsNetPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.netConn.ReadFrom(p)
	if n > 0 {
		c.metrics.observeTraffic(c.labels, "uplink", int64(n))
	}
	return n, addr, err
}

func (c *metricsNetPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.netConn.WriteTo(p, addr)
	if n > 0 {
		c.metrics.observeTraffic(c.labels, "downlink", int64(n))
	}
	return n, err
}
