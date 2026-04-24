package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/openai/pitchprox/internal/config"
	"github.com/openai/pitchprox/internal/monitor"
)

type RouteResult struct {
	RuleID   string
	RuleName string
	Action   config.RuleAction
	ProxyID  string
	ChainID  string
	Hostname string
}

type RouteFunc func(flow Flow, sniff SniffResult) (RouteResult, config.Config, error)

type Server struct {
	IPv4Addr     string
	IPv6Addr     string
	Port         int
	SniffBytes   int
	SniffTimeout time.Duration
	Flows        *FlowTable
	Route        RouteFunc
	Monitor      *monitor.Bus

	listeners []net.Listener
	wg        sync.WaitGroup
	cancel    context.CancelFunc
}

var relayBufPool = sync.Pool{New: func() any {
	buf := make([]byte, 32*1024)
	return &buf
}}

const (
	trafficFlushEvery = 750 * time.Millisecond
	trafficFlushBytes = 256 * 1024
)

func (s *Server) Start(ctx context.Context) error {
	if s.Flows == nil {
		return fmt.Errorf("flows is nil")
	}
	if s.Route == nil {
		return fmt.Errorf("route callback is nil")
	}
	if s.IPv4Addr == "" {
		s.IPv4Addr = "0.0.0.0"
	}
	if s.IPv6Addr == "" {
		s.IPv6Addr = "::"
	}
	if s.SniffTimeout <= 0 {
		s.SniffTimeout = 1500 * time.Millisecond
	}
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	binds := []struct{ network, addr string }{
		{"tcp4", net.JoinHostPort(s.IPv4Addr, fmt.Sprintf("%d", s.Port))},
		{"tcp6", net.JoinHostPort(s.IPv6Addr, fmt.Sprintf("%d", s.Port))},
	}
	for _, bind := range binds {
		ln, err := net.Listen(bind.network, bind.addr)
		if err != nil {
			if bind.network == "tcp6" {
				continue
			}
			cancel()
			s.closeListeners()
			return fmt.Errorf("listen %s %s: %w", bind.network, bind.addr, err)
		}
		s.listeners = append(s.listeners, ln)
		s.wg.Add(1)
		go s.acceptLoop(ctx, ln)
	}
	if len(s.listeners) == 0 {
		cancel()
		return fmt.Errorf("no listeners started")
	}
	return nil
}

func (s *Server) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	s.closeListeners()
	s.wg.Wait()
	return nil
}

func (s *Server) closeListeners() {
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	s.listeners = nil
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if s.Monitor != nil {
				s.Monitor.AddLog("error", "transparent accept failed: %v", err)
			}
			time.Sleep(150 * time.Millisecond)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	clientAP, ok := addrPortFromNetAddr(conn.RemoteAddr())
	if !ok {
		return
	}
	flow, ok := s.Flows.Lookup(clientAP.Addr(), clientAP.Port())
	if !ok {
		if s.Monitor != nil {
			s.Monitor.AddLog("warn", "no flow for redirected connection from %s", clientAP)
		}
		return
	}
	s.Flows.Touch(flow.ClientIP, flow.ClientPort)
	defer s.Flows.Delete(flow.ClientIP, flow.ClientPort)

	br, sniff, err := PeekAndSniff(conn, s.SniffBytes, s.SniffTimeout)
	if err != nil && s.Monitor != nil {
		s.Monitor.AddLog("warn", "sniff failed for %s:%d: %v", flow.OriginalIP, flow.OriginalPort, err)
	}
	route, cfg, err := s.Route(flow, sniff)
	if err != nil {
		if s.Monitor != nil {
			s.Monitor.AddLog("error", "route resolution failed: %v", err)
		}
		return
	}

	connID := monitor.ConnID(flow.PID, flow.ClientIP, flow.ClientPort, flow.OriginalIP, flow.OriginalPort)
	baseConn := monitor.Connection{
		ID:           connID,
		PID:          flow.PID,
		ExePath:      flow.ExePath,
		SourceIP:     flow.ClientIP.String(),
		SourcePort:   flow.ClientPort,
		OriginalIP:   flow.OriginalIP.String(),
		OriginalPort: flow.OriginalPort,
		Hostname:     route.Hostname,
		RuleID:       route.RuleID,
		RuleName:     route.RuleName,
		Action:       route.Action,
		ProxyID:      route.ProxyID,
		ChainID:      route.ChainID,
		State:        "opening",
	}
	if s.Monitor != nil {
		s.Monitor.UpsertConnection(baseConn)
		s.Monitor.AddRuleConnection(route.RuleID, route.RuleName, route.Action)
	}

	if route.Action == config.ActionBlock {
		if s.Monitor != nil {
			blocked := baseConn
			blocked.State = "blocked"
			s.Monitor.UpsertConnection(blocked)
			s.Monitor.AddConnectionLog("info", blocked, "blocked pid=%d exe=%s host=%s dst=%s:%d rule=%s", flow.PID, flow.ExePath, displayHost(route.Hostname, flow.OriginalIP), flow.OriginalIP, flow.OriginalPort, route.RuleName)
		}
		return
	}

	dialAddress := net.JoinHostPort(flow.OriginalIP.String(), fmt.Sprintf("%d", flow.OriginalPort))
	if (route.Action == config.ActionProxy || route.Action == config.ActionChain) && route.Hostname != "" {
		dialAddress = net.JoinHostPort(route.Hostname, fmt.Sprintf("%d", flow.OriginalPort))
	}
	dialer, err := BuildDialer(cfg, route.Action, route.ProxyID, route.ChainID)
	if err != nil {
		if s.Monitor != nil {
			failed := baseConn
			failed.State = "error"
			s.Monitor.UpsertConnection(failed)
			s.Monitor.AddConnectionLog("error", failed, "build dialer failed action=%s proxy=%s chain=%s err=%v", route.Action, route.ProxyID, route.ChainID, err)
		}
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	upstream, err := dialer.DialContext(dialCtx, family(flow), dialAddress)
	cancel()
	if err != nil {
		if s.Monitor != nil {
			failed := baseConn
			failed.State = "error"
			s.Monitor.UpsertConnection(failed)
			s.Monitor.AddConnectionLog("error", failed, "upstream dial failed host=%s dst=%s:%d via=%s err=%v", displayHost(route.Hostname, flow.OriginalIP), flow.OriginalIP, flow.OriginalPort, dialAddress, err)
		}
		return
	}
	defer upstream.Close()

	if s.Monitor != nil {
		opened := baseConn
		opened.State = "open"
		s.Monitor.UpsertConnection(opened)
		s.Monitor.AddConnectionLog("info", opened, "opened pid=%d exe=%s action=%s host=%s dst=%s:%d via=%s", flow.PID, flow.ExePath, route.Action, displayHost(route.Hostname, flow.OriginalIP), flow.OriginalIP, flow.OriginalPort, dialAddress)
	}

	var trafficFn func(int64, int64)
	if s.Monitor != nil {
		recorder := newTrafficRecorder(func(upBytes, downBytes int64) {
			s.Monitor.AddRuleTraffic(route.RuleID, route.RuleName, route.Action, upBytes, downBytes)
			if route.Action == config.ActionProxy || route.Action == config.ActionChain {
				s.Monitor.AddTraffic(route.Action, upBytes, downBytes)
			}
		})
		defer recorder.Flush()
		trafficFn = recorder.Add
	}

	appSide := &prefixedConn{Conn: conn, Reader: br}
	done := make(chan copyResult, 2)
	go relayCopy(upstream, appSide, func(n int64) {
		if trafficFn != nil {
			trafficFn(n, 0)
		}
	}, done, "up")
	go relayCopy(appSide, upstream, func(n int64) {
		if trafficFn != nil {
			trafficFn(0, n)
		}
	}, done, "down")

	first := <-done
	_ = conn.SetDeadline(time.Now())
	_ = upstream.SetDeadline(time.Now())
	second := <-done
	upBytes, downBytes := mergeCopyResults(first, second)

	if s.Monitor != nil {
		closed := baseConn
		closed.State = "closed"
		closed.BytesUp = upBytes
		closed.BytesDown = downBytes
		s.Monitor.UpsertConnection(closed)
		s.Monitor.AddConnectionLog("info", closed, "closed pid=%d exe=%s action=%s host=%s dst=%s:%d bytes_up=%d bytes_down=%d", flow.PID, flow.ExePath, route.Action, displayHost(route.Hostname, flow.OriginalIP), flow.OriginalIP, flow.OriginalPort, upBytes, downBytes)
	}
}

type copyResult struct {
	Direction string
	Bytes     int64
}

func relayCopy(dst net.Conn, src io.Reader, onChunk func(int64), done chan<- copyResult, direction string) {
	bufPtr := relayBufPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayBufPool.Put(bufPtr)
	var total int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			written := 0
			for written < nr {
				nw, ew := dst.Write(buf[written:nr])
				if nw > 0 {
					written += nw
					total += int64(nw)
					if onChunk != nil {
						onChunk(int64(nw))
					}
				}
				if ew != nil || nw == 0 {
					break
				}
			}
			if written < nr {
				break
			}
		}
		if er != nil {
			break
		}
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	done <- copyResult{Direction: direction, Bytes: total}
}

func mergeCopyResults(a, b copyResult) (int64, int64) {
	var upBytes, downBytes int64
	for _, item := range []copyResult{a, b} {
		switch item.Direction {
		case "up":
			upBytes = item.Bytes
		case "down":
			downBytes = item.Bytes
		}
	}
	return upBytes, downBytes
}

type prefixedConn struct {
	net.Conn
	Reader *bufio.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }

type trafficRecorder struct {
	mu        sync.Mutex
	flushFn   func(int64, int64)
	pendingUp int64
	pendingDn int64
	lastFlush time.Time
}

func newTrafficRecorder(flushFn func(int64, int64)) *trafficRecorder {
	return &trafficRecorder{flushFn: flushFn, lastFlush: time.Now().UTC()}
}

func (r *trafficRecorder) Add(upBytes, downBytes int64) {
	if r == nil || r.flushFn == nil || (upBytes == 0 && downBytes == 0) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pendingUp += upBytes
	r.pendingDn += downBytes
	now := time.Now().UTC()
	if now.Sub(r.lastFlush) >= trafficFlushEvery || (r.pendingUp+r.pendingDn) >= trafficFlushBytes {
		r.flushLocked(now)
	}
}

func (r *trafficRecorder) Flush() {
	if r == nil || r.flushFn == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flushLocked(time.Now().UTC())
}

func (r *trafficRecorder) flushLocked(now time.Time) {
	if r.pendingUp == 0 && r.pendingDn == 0 {
		r.lastFlush = now
		return
	}
	r.flushFn(r.pendingUp, r.pendingDn)
	r.pendingUp = 0
	r.pendingDn = 0
	r.lastFlush = now
}

func addrPortFromNetAddr(a net.Addr) (netip.AddrPort, bool) {
	ta, ok := a.(*net.TCPAddr)
	if !ok || ta.IP == nil {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(ta.Port)), true
}

func family(flow Flow) string {
	if flow.IPv6 {
		return "tcp6"
	}
	return "tcp4"
}

func displayHost(host string, ip netip.Addr) string {
	if host != "" {
		return host
	}
	return ip.String()
}
