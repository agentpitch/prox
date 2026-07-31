//go:build !windows

package windivert

import (
	"context"
	"fmt"

	"github.com/agentpitch/prox/internal/config"
	"github.com/agentpitch/prox/internal/monitor"
	"github.com/agentpitch/prox/internal/proxy"
)

type PlanDecision struct {
	Definitive    bool
	NeedsHostname bool
	RuleID        string
	RuleName      string
	Action        config.RuleAction
	ProxyID       string
	ChainID       string
}

type PlanFunc func(flow proxy.Flow) PlanDecision

type Engine struct {
	ListenerPort int
	Flows        *proxy.FlowTable
	Monitor      *monitor.Bus
	Plan         PlanFunc
}

func (e *Engine) Start(ctx context.Context) error { return fmt.Errorf("windows only") }
func (e *Engine) Close() error                    { return nil }
