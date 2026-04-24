//go:build windows

package httpapi

import (
	"net/http"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetProcessHandleCount = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")

func TestServerConnectionChurnDoesNotLeakWindowsHandles(t *testing.T) {
	addr := freeHTTPAddr(t)
	srv, err := New(addr, newFakeRuntime(t, addr), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve() }()
	defer func() {
		_ = srv.Close()
		<-done
	}()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	runHealthRequests(t, client, addr, 25)
	waitNoTrackedConnections(t, srv)
	before, err := currentProcessHandleCount()
	if err != nil {
		t.Fatalf("handle count before churn: %v", err)
	}
	beforeHeap := currentHeapAlloc()

	runHealthRequests(t, client, addr, 1000)
	waitNoTrackedConnections(t, srv)
	after, err := currentProcessHandleCount()
	if err != nil {
		t.Fatalf("handle count after churn: %v", err)
	}
	afterHeap := currentHeapAlloc()
	t.Logf("process handles before=%d after=%d delta=%d", before, after, int64(after)-int64(before))
	t.Logf("heap alloc before=%d after=%d delta=%d", beforeHeap, afterHeap, int64(afterHeap)-int64(beforeHeap))

	const tolerance = 16
	if after > before+tolerance {
		t.Fatalf("process handles grew from %d to %d after connection churn, tolerance %d", before, after, tolerance)
	}
	const heapTolerance = 4 << 20
	if afterHeap > beforeHeap+heapTolerance {
		t.Fatalf("heap grew from %d to %d after connection churn, tolerance %d", beforeHeap, afterHeap, heapTolerance)
	}
}

func runHealthRequests(t *testing.T, client *http.Client, addr string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		resp, err := client.Get("http://" + addr + "/api/health")
		if err != nil {
			t.Fatalf("GET health #%d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET health #%d status = %d, want 200", i, resp.StatusCode)
		}
	}
}

func currentProcessHandleCount() (uint32, error) {
	var count uint32
	r1, _, err := procGetProcessHandleCount.Call(^uintptr(0), uintptr(unsafe.Pointer(&count)))
	if r1 == 0 {
		return 0, err
	}
	return count, nil
}

func currentHeapAlloc() uint64 {
	runtime.GC()
	debug.FreeOSMemory()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}
