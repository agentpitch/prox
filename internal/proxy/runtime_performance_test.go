package proxy

import (
	"bufio"
	"net/netip"
	"strings"
	"testing"
)

func BenchmarkPeekSniffHTTPBuffered(b *testing.B) {
	request := "GET / HTTP/1.1\r\nX-Padding: " + strings.Repeat("x", 3000) + "\r\nHost: example.com\r\n\r\n"
	b.ReportAllocs()
	b.SetBytes(int64(len(request)))
	for i := 0; i < b.N; i++ {
		reader := bufio.NewReaderSize(strings.NewReader(request), 4096)
		if _, err := peekSniffData(reader, 4096); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFlowTableChurnWithLongLivedFlows(b *testing.B) {
	table := benchmarkFlowTable(4096)
	flow, _ := table.Lookup(netip.MustParseAddr("192.0.2.10"), 40000)
	flow.ClientPort = 60000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table.Register(flow)
		table.Delete(flow.ClientIP, flow.ClientPort)
	}
}
