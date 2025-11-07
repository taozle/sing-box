package experimental

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/prometheus"
	"github.com/sagernet/sing-box/option"
)

func NewPrometheusService(ctx context.Context, options option.PrometheusOptions) (adapter.LifecycleService, error) {
	return prometheus.NewService(ctx, options)
}
