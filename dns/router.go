package dns

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox/platform"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

var _ adapter.DNSRouter = (*Router)(nil)

type Router struct {
	ctx                   context.Context
	logger                logger.ContextLogger
	transport             adapter.DNSTransportManager
	outbound              adapter.OutboundManager
	client                adapter.DNSClient
	rules                 []adapter.DNSRule
	defaultDomainStrategy C.DomainStrategy
	dnsReverseMapping     freelru.Cache[netip.Addr, string]
	platformInterface     platform.Interface
	trackers              []adapter.DNSTracker
}

func NewRouter(ctx context.Context, logFactory log.Factory, options option.DNSOptions) *Router {
	router := &Router{
		ctx:                   ctx,
		logger:                logFactory.NewLogger("dns"),
		transport:             service.FromContext[adapter.DNSTransportManager](ctx),
		outbound:              service.FromContext[adapter.OutboundManager](ctx),
		rules:                 make([]adapter.DNSRule, 0, len(options.Rules)),
		defaultDomainStrategy: C.DomainStrategy(options.Strategy),
	}
	router.client = NewClient(ClientOptions{
		DisableCache:     options.DNSClientOptions.DisableCache,
		DisableExpire:    options.DNSClientOptions.DisableExpire,
		IndependentCache: options.DNSClientOptions.IndependentCache,
		CacheCapacity:    options.DNSClientOptions.CacheCapacity,
		ClientSubnet:     options.DNSClientOptions.ClientSubnet.Build(netip.Prefix{}),
		RDRC: func() adapter.RDRCStore {
			cacheFile := service.FromContext[adapter.CacheFile](ctx)
			if cacheFile == nil {
				return nil
			}
			if !cacheFile.StoreRDRC() {
				return nil
			}
			return cacheFile
		},
		Logger: router.logger,
	})
	if options.ReverseMapping {
		router.dnsReverseMapping = common.Must1(freelru.NewSharded[netip.Addr, string](1024, maphash.NewHasher[netip.Addr]().Hash32))
	}
	return router
}

func (r *Router) Initialize(rules []option.DNSRule) error {
	for i, ruleOptions := range rules {
		dnsRule, err := R.NewDNSRule(r.ctx, r.logger, ruleOptions, true)
		if err != nil {
			return E.Cause(err, "parse dns rule[", i, "]")
		}
		r.rules = append(r.rules, dnsRule)
	}
	return nil
}

func (r *Router) Start(stage adapter.StartStage) error {
	monitor := taskmonitor.New(r.logger, C.StartTimeout)
	switch stage {
	case adapter.StartStateStart:
		monitor.Start("initialize DNS client")
		r.client.Start()
		monitor.Finish()

		for i, rule := range r.rules {
			monitor.Start("initialize DNS rule[", i, "]")
			err := rule.Start()
			monitor.Finish()
			if err != nil {
				return E.Cause(err, "initialize DNS rule[", i, "]")
			}
		}
	}
	return nil
}

func (r *Router) Close() error {
	monitor := taskmonitor.New(r.logger, C.StopTimeout)
	var err error
	for i, rule := range r.rules {
		monitor.Start("close dns rule[", i, "]")
		err = E.Append(err, rule.Close(), func(err error) error {
			return E.Cause(err, "close dns rule[", i, "]")
		})
		monitor.Finish()
	}
	return err
}

func (r *Router) matchDNS(ctx context.Context, allowFakeIP bool, ruleIndex int, isAddressQuery bool, options *adapter.DNSQueryOptions) (adapter.DNSTransport, adapter.DNSRule, int) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		panic("no context")
	}
	var currentRuleIndex int
	if ruleIndex != -1 {
		currentRuleIndex = ruleIndex + 1
	}
	for ; currentRuleIndex < len(r.rules); currentRuleIndex++ {
		currentRule := r.rules[currentRuleIndex]
		if currentRule.WithAddressLimit() && !isAddressQuery {
			continue
		}
		metadata.ResetRuleCache()
		if currentRule.Match(metadata) {
			displayRuleIndex := currentRuleIndex
			if displayRuleIndex != -1 {
				displayRuleIndex += displayRuleIndex + 1
			}
			ruleDescription := currentRule.String()
			if ruleDescription != "" {
				r.logger.DebugContext(ctx, "match[", displayRuleIndex, "] ", currentRule, " => ", currentRule.Action())
			} else {
				r.logger.DebugContext(ctx, "match[", displayRuleIndex, "] => ", currentRule.Action())
			}
			switch action := currentRule.Action().(type) {
			case *R.RuleActionDNSRoute:
				transport, loaded := r.transport.Transport(action.Server)
				if !loaded {
					r.logger.ErrorContext(ctx, "transport not found: ", action.Server)
					continue
				}
				isFakeIP := transport.Type() == C.DNSTypeFakeIP
				if isFakeIP && !allowFakeIP {
					continue
				}
				if action.Strategy != C.DomainStrategyAsIS {
					options.Strategy = action.Strategy
				}
				if isFakeIP || action.DisableCache {
					options.DisableCache = true
				}
				if action.RewriteTTL != nil {
					options.RewriteTTL = action.RewriteTTL
				}
				if action.ClientSubnet.IsValid() {
					options.ClientSubnet = action.ClientSubnet
				}
				if legacyTransport, isLegacy := transport.(adapter.LegacyDNSTransport); isLegacy {
					if options.Strategy == C.DomainStrategyAsIS {
						options.Strategy = legacyTransport.LegacyStrategy()
					}
					if !options.ClientSubnet.IsValid() {
						options.ClientSubnet = legacyTransport.LegacyClientSubnet()
					}
				}
				return transport, currentRule, currentRuleIndex
			case *R.RuleActionDNSRouteOptions:
				if action.Strategy != C.DomainStrategyAsIS {
					options.Strategy = action.Strategy
				}
				if action.DisableCache {
					options.DisableCache = true
				}
				if action.RewriteTTL != nil {
					options.RewriteTTL = action.RewriteTTL
				}
				if action.ClientSubnet.IsValid() {
					options.ClientSubnet = action.ClientSubnet
				}
			case *R.RuleActionReject:
				return nil, currentRule, currentRuleIndex
			case *R.RuleActionPredefined:
				return nil, currentRule, currentRuleIndex
			}
		}
	}
	return r.transport.Default(), nil, -1
}

func (r *Router) AppendDNSTracker(tracker adapter.DNSTracker) {
	r.trackers = append(r.trackers, tracker)
}

func (r *Router) notifyDNSTrackers(ctx context.Context, observation adapter.DNSQueryObservation) {
	if len(r.trackers) == 0 {
		return
	}
	for _, tracker := range r.trackers {
		tracker.ObserveDNSQuery(ctx, observation)
	}
}

func (r *Router) Exchange(ctx context.Context, message *mDNS.Msg, options adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	if len(message.Question) != 1 {
		r.logger.WarnContext(ctx, "bad question size: ", len(message.Question))
		responseMessage := mDNS.Msg{
			MsgHdr: mDNS.MsgHdr{
				Id:       message.Id,
				Response: true,
				Rcode:    mDNS.RcodeFormatError,
			},
			Question: message.Question,
		}
		return &responseMessage, nil
	}
	question := message.Question[0]
	r.logger.DebugContext(ctx, "exchange ", FormatQuestion(question.String()))
	observation := adapter.DNSQueryObservation{
		Question: question,
		Options:  options,
		RCode:    -1,
	}
	start := time.Now()
	var notify bool
	defer func() {
		if !notify {
			return
		}
		if !observation.Cached && observation.Duration == 0 {
			observation.Duration = time.Since(start)
		}
		r.notifyDNSTrackers(ctx, observation)
	}()
	response, cached := r.client.ExchangeCache(ctx, message)
	var metadata *adapter.InboundContext
	if cached {
		metadata = &adapter.InboundContext{}
	} else {
		ctx, metadata = adapter.ExtendContext(ctx)
	}
	metadata.Destination = M.Socksaddr{}
	metadata.QueryType = question.Qtype
	switch metadata.QueryType {
	case mDNS.TypeA:
		metadata.IPVersion = 4
	case mDNS.TypeAAAA:
		metadata.IPVersion = 6
	}
	metadata.Domain = FqdnToDomain(question.Name)
	observation.Metadata = metadata
	if cached {
		observation.Cached = true
		if response != nil {
			observation.RCode = response.Rcode
		}
		notify = true
		return response, nil
	}
	var (
		transport adapter.DNSTransport
		err       error
	)
	if options.Transport != nil {
		transport = options.Transport
		if legacyTransport, isLegacy := transport.(adapter.LegacyDNSTransport); isLegacy {
			if options.Strategy == C.DomainStrategyAsIS {
				options.Strategy = legacyTransport.LegacyStrategy()
			}
			if !options.ClientSubnet.IsValid() {
				options.ClientSubnet = legacyTransport.LegacyClientSubnet()
			}
		}
		if options.Strategy == C.DomainStrategyAsIS {
			options.Strategy = r.defaultDomainStrategy
		}
		observation.Transport = transport
		observation.Options = options
		exchangeStart := time.Now()
		response, err = r.client.Exchange(ctx, transport, message, options, nil)
		observation.Duration = time.Since(exchangeStart)
		observation.Err = err
		if response != nil {
			observation.RCode = response.Rcode
		}
	} else {
		var (
			rule      adapter.DNSRule
			ruleIndex int
		)
		ruleIndex = -1
		for {
			dnsCtx := adapter.OverrideContext(ctx)
			dnsOptions := options
			transport, rule, ruleIndex = r.matchDNS(ctx, true, ruleIndex, isAddressQuery(message), &dnsOptions)
			if rule != nil {
				switch action := rule.Action().(type) {
				case *R.RuleActionReject:
					switch action.Method {
					case C.RuleActionRejectMethodDefault:
						observation.Rule = rule
						observation.Err = nil
						observation.RCode = mDNS.RcodeRefused
						notify = true
						return &mDNS.Msg{
							MsgHdr: mDNS.MsgHdr{
								Id:       message.Id,
								Rcode:    mDNS.RcodeRefused,
								Response: true,
							},
							Question: []mDNS.Question{question},
						}, nil
					case C.RuleActionRejectMethodDrop:
						observation.Rule = rule
						observation.Err = tun.ErrDrop
						notify = true
						return nil, tun.ErrDrop
					}
				case *R.RuleActionPredefined:
					observation.Rule = rule
					observation.Err = nil
					responseMessage := action.Response(message)
					if responseMessage != nil {
						observation.RCode = responseMessage.Rcode
					}
					notify = true
					return responseMessage, nil
				}
			}
			var responseCheck func(responseAddrs []netip.Addr) bool
			if rule != nil && rule.WithAddressLimit() {
				responseCheck = func(responseAddrs []netip.Addr) bool {
					metadata.DestinationAddresses = responseAddrs
					return rule.MatchAddressLimit(metadata)
				}
			}
			if dnsOptions.Strategy == C.DomainStrategyAsIS {
				dnsOptions.Strategy = r.defaultDomainStrategy
			}
			observation.Transport = transport
			observation.Rule = rule
			observation.Options = dnsOptions
			exchangeStart := time.Now()
			response, err = r.client.Exchange(dnsCtx, transport, message, dnsOptions, responseCheck)
			observation.Duration = time.Since(exchangeStart)
			observation.Err = err
			if response != nil {
				observation.RCode = response.Rcode
			}
			var rejected bool
			if err != nil {
				if errors.Is(err, ErrResponseRejectedCached) {
					rejected = true
					r.logger.DebugContext(ctx, E.Cause(err, "response rejected for ", FormatQuestion(question.String())), " (cached)")
				} else if errors.Is(err, ErrResponseRejected) {
					rejected = true
					r.logger.DebugContext(ctx, E.Cause(err, "response rejected for ", FormatQuestion(question.String())))
				} else {
					r.logger.ErrorContext(ctx, E.Cause(err, "exchange failed for ", FormatQuestion(question.String())))
				}
			}
			if responseCheck != nil && rejected {
				continue
			}
			break
		}
	}
	notify = true
	if err != nil {
		return nil, err
	}
	if r.dnsReverseMapping != nil && len(message.Question) > 0 && response != nil && len(response.Answer) > 0 {
		if transport == nil || transport.Type() != C.DNSTypeFakeIP {
			for _, answer := range response.Answer {
				switch record := answer.(type) {
				case *mDNS.A:
					r.dnsReverseMapping.AddWithLifetime(M.AddrFromIP(record.A), FqdnToDomain(record.Hdr.Name), time.Duration(record.Hdr.Ttl)*time.Second)
				case *mDNS.AAAA:
					r.dnsReverseMapping.AddWithLifetime(M.AddrFromIP(record.AAAA), FqdnToDomain(record.Hdr.Name), time.Duration(record.Hdr.Ttl)*time.Second)
				}
			}
		}
	}
	return response, nil
}

func (r *Router) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	observation := adapter.DNSQueryObservation{
		Question: mDNS.Question{Name: mDNS.Fqdn(domain)},
		Options:  options,
		RCode:    -1,
	}
	start := time.Now()
	var notify bool
	var (
		responseAddrs []netip.Addr
		err           error
	)
	defer func() {
		if !notify {
			return
		}
		if !observation.Cached && observation.Duration == 0 {
			observation.Duration = time.Since(start)
		}
		r.notifyDNSTrackers(ctx, observation)
	}()
	responseAddrs, cached := r.client.LookupCache(domain, options.Strategy)
	if cached {
		observation.Cached = true
		observation.RCode = mDNS.RcodeSuccess
		if len(responseAddrs) == 0 {
			err = E.New("lookup ", domain, ": empty result (cached)")
			observation.Err = err
			notify = true
			return nil, err
		}
		observation.Err = nil
		notify = true
		return responseAddrs, nil
	}
	r.logger.DebugContext(ctx, "lookup domain ", domain)
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Destination = M.Socksaddr{}
	metadata.Domain = FqdnToDomain(domain)
	observation.Metadata = metadata
	if options.Transport != nil {
		transport := options.Transport
		if legacyTransport, isLegacy := transport.(adapter.LegacyDNSTransport); isLegacy {
			if options.Strategy == C.DomainStrategyAsIS {
				options.Strategy = r.defaultDomainStrategy
			}
			if !options.ClientSubnet.IsValid() {
				options.ClientSubnet = legacyTransport.LegacyClientSubnet()
			}
		}
		if options.Strategy == C.DomainStrategyAsIS {
			options.Strategy = r.defaultDomainStrategy
		}
		observation.Transport = transport
		observation.Options = options
		lookupStart := time.Now()
		responseAddrs, err = r.client.Lookup(ctx, transport, domain, options, nil)
		observation.Duration = time.Since(lookupStart)
		observation.Err = err
		if err == nil && len(responseAddrs) > 0 {
			observation.RCode = mDNS.RcodeSuccess
		}
	} else {
		var (
			transport adapter.DNSTransport
			rule      adapter.DNSRule
			ruleIndex int
		)
		ruleIndex = -1
		for {
			dnsCtx := adapter.OverrideContext(ctx)
			dnsOptions := options
			transport, rule, ruleIndex = r.matchDNS(ctx, false, ruleIndex, true, &dnsOptions)
			if rule != nil {
				switch action := rule.Action().(type) {
				case *R.RuleActionReject:
					switch action.Method {
					case C.RuleActionRejectMethodDefault:
						observation.Rule = rule
						observation.Err = nil
						observation.RCode = mDNS.RcodeRefused
						notify = true
						return nil, nil
					case C.RuleActionRejectMethodDrop:
						observation.Rule = rule
						observation.Err = tun.ErrDrop
						notify = true
						return nil, tun.ErrDrop
					}
				case *R.RuleActionPredefined:
					observation.Rule = rule
					if action.Rcode != mDNS.RcodeSuccess {
						err = RcodeError(action.Rcode)
						observation.Err = err
						observation.RCode = action.Rcode
					} else {
						for _, answer := range action.Answer {
							switch record := answer.(type) {
							case *mDNS.A:
								responseAddrs = append(responseAddrs, M.AddrFromIP(record.A))
							case *mDNS.AAAA:
								responseAddrs = append(responseAddrs, M.AddrFromIP(record.AAAA))
							}
						}
						observation.Err = nil
						if len(responseAddrs) > 0 {
							observation.RCode = mDNS.RcodeSuccess
						}
					}
					notify = true
					goto lookupResponse
				}
			}
			var responseCheck func(responseAddrs []netip.Addr) bool
			if rule != nil && rule.WithAddressLimit() {
				responseCheck = func(responseAddrs []netip.Addr) bool {
					metadata.DestinationAddresses = responseAddrs
					return rule.MatchAddressLimit(metadata)
				}
			}
			if dnsOptions.Strategy == C.DomainStrategyAsIS {
				dnsOptions.Strategy = r.defaultDomainStrategy
			}
			observation.Transport = transport
			observation.Rule = rule
			observation.Options = dnsOptions
			lookupStart := time.Now()
			responseAddrs, err = r.client.Lookup(dnsCtx, transport, domain, dnsOptions, responseCheck)
			observation.Duration = time.Since(lookupStart)
			observation.Err = err
			if err == nil && len(responseAddrs) > 0 {
				observation.RCode = mDNS.RcodeSuccess
			}
			if responseCheck == nil || err == nil {
				break
			}
			if errors.Is(err, ErrResponseRejectedCached) {
				r.logger.DebugContext(ctx, "response rejected for ", domain, " (cached)")
			} else if errors.Is(err, ErrResponseRejected) {
				r.logger.DebugContext(ctx, "response rejected for ", domain)
			} else {
				r.logger.ErrorContext(ctx, E.Cause(err, "lookup failed for ", domain))
			}
			err = E.Cause(err, "lookup ", domain)
			observation.Err = err
		}
	}
lookupResponse:
	if err == nil && len(responseAddrs) == 0 {
		err = E.New("empty result")
		observation.Err = err
	}
	if err != nil {
		if errors.Is(err, ErrResponseRejectedCached) {
			r.logger.DebugContext(ctx, "response rejected for ", domain, " (cached)")
		} else if errors.Is(err, ErrResponseRejected) {
			r.logger.DebugContext(ctx, "response rejected for ", domain)
		} else {
			r.logger.ErrorContext(ctx, E.Cause(err, "lookup failed for ", domain))
		}
		err = E.Cause(err, "lookup ", domain)
		observation.Err = err
	}
	if len(responseAddrs) > 0 {
		r.logger.InfoContext(ctx, "lookup succeed for ", domain, ": ", strings.Join(F.MapToString(responseAddrs), " "))
		if observation.RCode < 0 {
			observation.RCode = mDNS.RcodeSuccess
		}
	}
	notify = true
	return responseAddrs, err
}

func isAddressQuery(message *mDNS.Msg) bool {
	for _, question := range message.Question {
		if question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA || question.Qtype == mDNS.TypeHTTPS {
			return true
		}
	}
	return false
}

func (r *Router) ClearCache() {
	r.client.ClearCache()
	if r.platformInterface != nil {
		r.platformInterface.ClearDNSCache()
	}
}

func (r *Router) LookupReverseMapping(ip netip.Addr) (string, bool) {
	if r.dnsReverseMapping == nil {
		return "", false
	}
	domain, loaded := r.dnsReverseMapping.Get(ip)
	return domain, loaded
}

func (r *Router) ResetNetwork() {
	r.ClearCache()
	for _, transport := range r.transport.Transports() {
		transport.Close()
	}
}
