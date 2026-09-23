//go:build windows

package trayapp

import (
	"encoding/binary"
	"image"
	"image/color"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/agentpitch/prox/internal/monitor"
	"golang.org/x/sys/windows"
)

func TestEncodeIconDIBUsesUncompressedAlignedPixels(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	img.SetNRGBA(0, 15, color.NRGBA{R: 11, G: 22, B: 33, A: 44})

	data, err := encodeIconDIB(img)
	if err != nil {
		t.Fatalf("encodeIconDIB: %v", err)
	}
	const (
		dibHeader = 40
		xorBytes  = 16 * 16 * 4
		maskBytes = 16 * 4
		wantLen   = dibHeader + xorBytes + maskBytes
	)
	if len(data) != wantLen {
		t.Fatalf("DIB len = %d, want %d", len(data), wantLen)
	}
	if uintptr(unsafe.Pointer(&data[0]))%4 != 0 {
		t.Fatal("icon resource must be DWORD-aligned")
	}
	if got := binary.LittleEndian.Uint32(data[0:4]); got != dibHeader {
		t.Fatalf("DIB header size = %d, want %d", got, dibHeader)
	}
	if got := binary.LittleEndian.Uint32(data[8:12]); got != 32 {
		t.Fatalf("DIB height = %d, want 32", got)
	}
	firstPixel := data[dibHeader : dibHeader+4]
	if got := [4]byte{firstPixel[0], firstPixel[1], firstPixel[2], firstPixel[3]}; got != [4]byte{33, 22, 11, 44} {
		t.Fatalf("first BGRA pixel = %v, want [33 22 11 44]", got)
	}
}

func TestInMemoryIconsReleaseNativeResources(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	drawTrafficIconFrame(img)
	getGUIResources := windows.NewLazySystemDLL("user32.dll").NewProc("GetGuiResources")
	resourceCount := func() uintptr {
		t.Helper()
		count, _, _ := getGUIResources.Call(^uintptr(0), 1) // GR_USEROBJECTS
		return count
	}
	makeAndDestroy := func() {
		t.Helper()
		icon, err := createIcon(img)
		if err != nil {
			t.Fatal(err)
		}
		if ok, _, err := procDestroyIcon.Call(uintptr(icon)); ok == 0 {
			t.Fatalf("DestroyIcon: %v", err)
		}
	}
	makeAndDestroy() // Initialize USER32 before measuring steady state.
	before := resourceCount()
	for i := 0; i < 500; i++ {
		makeAndDestroy()
	}
	after := resourceCount()
	t.Logf("USER resources before=%d after=%d", before, after)
	if after > before+2 {
		t.Fatalf("icon churn leaked USER resources: %d -> %d", before, after)
	}
}

func TestPollerStopsBeforeFirstTick(t *testing.T) {
	h := &helper{}
	stop := h.startPolling()
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stopping the tray left its poller running")
	}
}

func TestCleanupDestroysHiddenWindowAndRejectsFurtherIcons(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	h := &helper{}
	if err := h.createWindow(); err != nil {
		t.Fatal(err)
	}
	h.cleanup()
	isWindow := windows.NewLazySystemDLL("user32.dll").NewProc("IsWindow")
	if exists, _, _ := isWindow.Call(uintptr(h.hwnd)); exists != 0 {
		t.Fatal("tray cleanup left its hidden window alive")
	}
	if err := h.updateIcon(nil, "", "late update"); err != nil {
		t.Fatal(err)
	}
	if h.iconHandle != 0 {
		t.Fatal("an icon was recreated after cleanup")
	}
}

func TestTrafficSeriesUsesFixedWindowWithoutMapGrowth(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	history, rx, tx, peakRx, peakTx := trafficSeries([]monitor.TrafficSample{
		{Time: now.Add(-2 * time.Second), UpBytes: 10, DownBytes: 20},
		{Time: now.Add(-2 * time.Second), UpBytes: 5, DownBytes: 7},
		{Time: now, UpBytes: 3, DownBytes: 4},
		{Time: now.Add(-time.Duration(trayHistorySeconds+1) * time.Second), UpBytes: 1000, DownBytes: 1000},
	})

	if got := len(history); got != trayHistorySeconds {
		t.Fatalf("history len = %d, want %d", got, trayHistorySeconds)
	}
	bucket := history[len(history)-3]
	if bucket.TxBytes != 15 || bucket.RxBytes != 27 {
		t.Fatalf("aggregated bucket = tx=%d rx=%d, want tx=15 rx=27", bucket.TxBytes, bucket.RxBytes)
	}
	if tx != 3 || rx != 4 {
		t.Fatalf("current = tx=%d rx=%d, want tx=3 rx=4", tx, rx)
	}
	if peakTx != 15 || peakRx != 27 {
		t.Fatalf("peaks = tx=%d rx=%d, want tx=15 rx=27", peakTx, peakRx)
	}
}

func TestTrafficIconFrameUsesHighContrastPixels(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	drawTrafficIconFrame(img)

	if got := img.NRGBAAt(0, 0); got.A < 200 || got.R < 220 {
		t.Fatalf("border pixel = %#v, want bright opaque border", got)
	}
	if got := img.NRGBAAt(8, 8); got.A < 230 || got.R > 40 || got.G > 60 || got.B < 30 {
		t.Fatalf("background pixel = %#v, want dark opaque background", got)
	}
}

func TestContextMenuOffersWebUIToggleAndFullPauseLabel(t *testing.T) {
	tests := []struct {
		name           string
		servicePaused  bool
		webUIAvailable bool
		webUIRunning   bool
		want           []menuItem
	}{
		{
			name:           "running WebUI",
			webUIAvailable: true,
			webUIRunning:   true,
			want: []menuItem{
				{command: menuManage, label: "Управление"},
				{command: menuPauseService, label: "Приостановить работу"},
				{command: menuDisableWebUI, label: "Отключить WebUI"},
				{command: menuExit, label: "Выйти"},
			},
		},
		{
			name:           "disabled WebUI",
			webUIAvailable: true,
			want: []menuItem{
				{command: menuManage, label: "Управление"},
				{command: menuPauseService, label: "Приостановить работу"},
				{command: menuEnableWebUI, label: "Включить WebUI"},
				{command: menuExit, label: "Выйти"},
			},
		},
		{
			name:          "paused service",
			servicePaused: true,
			want: []menuItem{
				{command: menuResumeService, label: "Запустить"},
				{command: menuExit, label: "Выйти"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := contextMenuItems(test.servicePaused, test.webUIAvailable, test.webUIRunning)
			if len(got) != len(test.want) {
				t.Fatalf("menu length = %d, want %d: %+v", len(got), len(test.want), got)
			}
			for i := range test.want {
				if got[i] != test.want[i] {
					t.Fatalf("menu item %d = %+v, want %+v", i, got[i], test.want[i])
				}
			}
		})
	}
}

func TestRemoteWebUIController(t *testing.T) {
	var enabled atomic.Bool
	var paused atomic.Bool
	enabled.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/control/webui/status":
			w.Header().Set("Content-Type", "application/json")
			if enabled.Load() {
				_, _ = w.Write([]byte(`{"enabled":true}`))
			} else {
				_, _ = w.Write([]byte(`{"enabled":false}`))
			}
		case "/api/control/webui/enable":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			enabled.Store(true)
			_, _ = w.Write([]byte(`{"enabled":true}`))
		case "/api/control/webui/disable":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			enabled.Store(false)
			_, _ = w.Write([]byte(`{"enabled":false}`))
		case "/api/control/service/status":
			w.Header().Set("Content-Type", "application/json")
			if paused.Load() {
				_, _ = w.Write([]byte(`{"paused":true,"webui_enabled":false}`))
			} else {
				_, _ = w.Write([]byte(`{"paused":false,"webui_enabled":true}`))
			}
		case "/api/control/service/pause":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			paused.Store(true)
			enabled.Store(false)
			_, _ = w.Write([]byte(`{"paused":true,"webui_enabled":false}`))
		case "/api/control/service/resume":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			paused.Store(false)
			enabled.Store(true)
			_, _ = w.Write([]byte(`{"paused":false,"webui_enabled":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	controller := remoteWebUIController{url: server.URL}
	if !controller.WebUIRunning() {
		t.Fatal("WebUIRunning = false, want true")
	}
	if err := controller.DisableWebUI(); err != nil {
		t.Fatalf("DisableWebUI: %v", err)
	}
	if controller.WebUIRunning() {
		t.Fatal("WebUIRunning = true after disable")
	}
	if err := controller.EnableWebUI(); err != nil {
		t.Fatalf("EnableWebUI: %v", err)
	}
	if !controller.WebUIRunning() {
		t.Fatal("WebUIRunning = false after enable")
	}
	if controller.ServicePaused() {
		t.Fatal("ServicePaused = true before pause")
	}
	if err := controller.PauseService(); err != nil {
		t.Fatalf("PauseService: %v", err)
	}
	if !controller.ServicePaused() {
		t.Fatal("ServicePaused = false after pause")
	}
	if err := controller.ResumeService(); err != nil {
		t.Fatalf("ResumeService: %v", err)
	}
	if controller.ServicePaused() {
		t.Fatal("ServicePaused = true after resume")
	}
}
