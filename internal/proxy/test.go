package proxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/openai/pitchprox/internal/config"
)

type ProxyTestResult struct {
	OK              bool   `json:"ok"`
	ProxyReachable  bool   `json:"proxy_reachable"`
	TunnelReachable bool   `json:"tunnel_reachable"`
	ProxyType       string `json:"proxy_type"`
	ProxyAddress    string `json:"proxy_address"`
	Target          string `json:"target"`
	DurationMS      int64  `json:"duration_ms"`
	Message         string `json:"message"`
}

func TestProxyProfile(ctx context.Context, pf config.ProxyProfile, target string) (ProxyTestResult, error) {
	started := time.Now()
	result := ProxyTestResult{
		ProxyType:    pf.Type,
		ProxyAddress: strings.TrimSpace(pf.Address),
	}
	if pf.Type == "" {
		return result, fmt.Errorf("proxy type is required")
	}
	if result.ProxyAddress == "" {
		return result, fmt.Errorf("proxy address is required")
	}
	normalizedTarget, err := normalizeProxyTestTarget(target)
	if err != nil {
		return result, err
	}
	result.Target = normalizedTarget

	baseCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	probeConn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(baseCtx, "tcp", result.ProxyAddress)
	if err != nil {
		result.DurationMS = time.Since(started).Milliseconds()
		result.Message = fmt.Sprintf("Proxy %s недоступен: %v", result.ProxyAddress, err)
		return result, nil
	}
	result.ProxyReachable = true
	_ = probeConn.Close()

	dialer, err := wrapDialer(DirectDialer(8*time.Second), pf)
	if err != nil {
		return result, err
	}
	tunnelCtx, cancelTunnel := context.WithTimeout(ctx, 10*time.Second)
	defer cancelTunnel()
	tunnelConn, err := dialer.DialContext(tunnelCtx, "tcp", normalizedTarget)
	if err != nil {
		result.DurationMS = time.Since(started).Milliseconds()
		result.Message = fmt.Sprintf("Proxy %s отвечает, но туннель до %s не открыт: %v", result.ProxyAddress, normalizedTarget, err)
		return result, nil
	}
	result.TunnelReachable = true
	result.OK = true
	result.DurationMS = time.Since(started).Milliseconds()
	result.Message = fmt.Sprintf("Proxy %s работает, туннель до %s открыт", result.ProxyAddress, normalizedTarget)
	_ = tunnelConn.Close()
	return result, nil
}

func normalizeProxyTestTarget(target string) (string, error) {
	v := strings.TrimSpace(target)
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	if v == "" {
		v = "www.google.com:443"
	}
	if !strings.Contains(v, ":") {
		v += ":443"
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return "", fmt.Errorf("invalid target %q: use host:port", target)
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("invalid target %q: use host:port", target)
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port), nil
}
