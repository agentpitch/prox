package proxy

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/pitchprox/internal/config"
)

func TestServerCloseClosesActiveRelayConnections(t *testing.T) {
	upstreamLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer upstreamLn.Close()
	upstreamAccepted := make(chan net.Conn, 1)
	go func() {
		conn, err := upstreamLn.Accept()
		if err == nil {
			upstreamAccepted <- conn
		}
	}()

	transparentLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("transparent listen: %v", err)
	}
	client, err := net.Dial("tcp4", transparentLn.Addr().String())
	if err != nil {
		t.Fatalf("dial transparent listener: %v", err)
	}
	defer client.Close()
	serverConn, err := transparentLn.Accept()
	if err != nil {
		t.Fatalf("accept transparent connection: %v", err)
	}
	_ = transparentLn.Close()

	clientTCP := client.LocalAddr().(*net.TCPAddr)
	upstreamTCP := upstreamLn.Addr().(*net.TCPAddr)
	flows := NewFlowTable()
	flows.Register(Flow{
		PID:          1,
		ClientIP:     netip.MustParseAddr("127.0.0.1"),
		ClientPort:   uint16(clientTCP.Port),
		OriginalIP:   netip.MustParseAddr("127.0.0.1"),
		OriginalPort: uint16(upstreamTCP.Port),
	})

	var routed atomic.Bool
	srv := &Server{
		SniffBytes:   1,
		SniffTimeout: 50 * time.Millisecond,
		Flows:        flows,
		Route: func(flow Flow, sniff SniffResult) (RouteResult, config.Config, error) {
			routed.Store(true)
			return RouteResult{Action: config.ActionDirect}, config.Config{}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		srv.handleConn(ctx, serverConn)
	}()
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatalf("write client preface: %v", err)
	}

	var upstream net.Conn
	select {
	case upstream = <-upstreamAccepted:
		defer upstream.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("upstream was not accepted")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if routed.Load() && srv.activeConnCountForTest() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := srv.activeConnCountForTest(); got < 2 {
		t.Fatalf("active conns = %d, want client and upstream tracked", got)
	}

	done := make(chan struct{})
	go func() {
		_ = srv.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Server.Close did not unblock active relay")
	}
	if got := srv.activeConnCountForTest(); got != 0 {
		t.Fatalf("active conns after close = %d, want 0", got)
	}
}

func (s *Server) activeConnCountForTest() int {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	return len(s.activeConns)
}
