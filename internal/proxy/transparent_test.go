package proxy

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentpitch/prox/internal/config"
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

type trackedConnStub struct{ id int }

func (*trackedConnStub) Read([]byte) (int, error)         { return 0, io.EOF }
func (*trackedConnStub) Write(p []byte) (int, error)      { return len(p), nil }
func (*trackedConnStub) Close() error                     { return nil }
func (*trackedConnStub) LocalAddr() net.Addr              { return nil }
func (*trackedConnStub) RemoteAddr() net.Addr             { return nil }
func (*trackedConnStub) SetDeadline(time.Time) error      { return nil }
func (*trackedConnStub) SetReadDeadline(time.Time) error  { return nil }
func (*trackedConnStub) SetWriteDeadline(time.Time) error { return nil }

func TestServerActiveConnectionsCompactAfterBurstWithSurvivor(t *testing.T) {
	const total = 1024
	srv := &Server{}
	conns := make([]net.Conn, total)
	for i := range conns {
		conns[i] = &trackedConnStub{id: i}
		srv.trackActiveConn(conns[i])
	}

	for _, conn := range conns[:total-1] {
		srv.untrackActiveConn(conn)
	}

	srv.activeMu.Lock()
	live := len(srv.activeConns)
	peak := srv.activePeak
	_, survivorTracked := srv.activeConns[conns[total-1]]
	srv.activeMu.Unlock()
	if live != 1 {
		t.Fatalf("active conns after burst = %d, want 1", live)
	}
	if !survivorTracked {
		t.Fatal("long-lived survivor was lost during map compaction")
	}
	if peak >= activeConnCompactMinPeak {
		t.Fatalf("active peak after compaction = %d, want below %d", peak, activeConnCompactMinPeak)
	}

	srv.untrackActiveConn(conns[total-1])
	srv.activeMu.Lock()
	live = len(srv.activeConns)
	peak = srv.activePeak
	srv.activeMu.Unlock()
	if live != 0 || peak != 0 {
		t.Fatalf("active state after final delete = len %d peak %d, want both zero", live, peak)
	}
}
