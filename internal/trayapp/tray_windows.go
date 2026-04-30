//go:build windows

package trayapp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/openai/pitchprox/internal/monitor"
	"github.com/openai/pitchprox/internal/util"
	"golang.org/x/sys/windows"
)

const (
	wmNull             = 0x0000
	wmApp              = 0x8000
	wmCommand          = 0x0111
	wmDestroy          = 0x0002
	wmClose            = 0x0010
	wmLButtonDblClk    = 0x0203
	wmRButtonUp        = 0x0205
	wmContextMenu      = 0x007B
	trayMessage        = wmApp + 1
	imageIcon          = 1
	lrLoadFromFile     = 0x0010
	nimAdd             = 0x00000000
	nimModify          = 0x00000001
	nimDelete          = 0x00000002
	nimSetFocus        = 0x00000003
	nimSetVersion      = 0x00000004
	nifMessage         = 0x00000001
	nifIcon            = 0x00000002
	nifTip             = 0x00000004
	notificationVer4   = 4
	mfString           = 0x00000000
	tpmLeftAlign       = 0x0000
	tpmRightAlign      = 0x0008
	tpmTopAlign        = 0x0000
	tpmBottomAlign     = 0x0020
	tpmRightButton     = 0x0002
	tpmReturnCmd       = 0x0100
	tpmNoNotify        = 0x0080
	swpNoSize          = 0x0001
	swpNoMove          = 0x0002
	swpNoActivate      = 0x0010
	monitorDefaultNear = 0x00000002
	ninKeySelect       = 0x0401
	menuManage         = 1001
	menuExit           = 1002
	menuDisableWebUI   = 1003
	menuPauseService   = 1004
	menuResumeService  = 1005
	offlineExitAfter   = 15 * time.Second
	pollInterval       = 2 * time.Second
	trayHistorySeconds = 12
	trayMinScaleBytes  = 5 * 1024
)

type Provider interface {
	TrayView(seconds int) (monitor.TrayView, error)
	OpenURL() string
	RequestStop() error
}

type WebUIController interface {
	WebUIRunning() bool
	EnableWebUI() error
	DisableWebUI() error
}

type ServiceController interface {
	ServicePaused() bool
	PauseService() error
	ResumeService() error
}

type remoteWebUIController struct {
	url string
}

type Options struct {
	URL      string
	Provider Provider
}

type point struct {
	X int32
	Y int32
}

type msg struct {
	Hwnd     windows.Handle
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       point
	LPrivate uint32
}

type wndClassEx struct {
	CbSize     uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type rect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type monitorInfo struct {
	CbSize    uint32
	RcMonitor rect
	RcWork    rect
	DwFlags   uint32
}

type notifyIconData struct {
	CbSize           uint32
	Wnd              windows.Handle
	UID              uint32
	Flags            uint32
	CallbackMessage  uint32
	Icon             windows.Handle
	Tip              [128]uint16
	State            uint32
	StateMask        uint32
	Info             [256]uint16
	TimeoutOrVersion uint32
	InfoTitle        [64]uint16
	InfoFlags        uint32
	GuidItem         windows.GUID
	BalloonIcon      windows.Handle
}

var (
	procRegisterClassExW    = windows.NewLazySystemDLL("user32.dll").NewProc("RegisterClassExW")
	procCreateWindowExW     = windows.NewLazySystemDLL("user32.dll").NewProc("CreateWindowExW")
	procDefWindowProcW      = windows.NewLazySystemDLL("user32.dll").NewProc("DefWindowProcW")
	procGetMessageW         = windows.NewLazySystemDLL("user32.dll").NewProc("GetMessageW")
	procTranslateMessage    = windows.NewLazySystemDLL("user32.dll").NewProc("TranslateMessage")
	procDispatchMessageW    = windows.NewLazySystemDLL("user32.dll").NewProc("DispatchMessageW")
	procPostQuitMessage     = windows.NewLazySystemDLL("user32.dll").NewProc("PostQuitMessage")
	procPostMessageW        = windows.NewLazySystemDLL("user32.dll").NewProc("PostMessageW")
	procShellNotifyIconW    = windows.NewLazySystemDLL("shell32.dll").NewProc("Shell_NotifyIconW")
	procCreatePopupMenu     = windows.NewLazySystemDLL("user32.dll").NewProc("CreatePopupMenu")
	procAppendMenuW         = windows.NewLazySystemDLL("user32.dll").NewProc("AppendMenuW")
	procTrackPopupMenu      = windows.NewLazySystemDLL("user32.dll").NewProc("TrackPopupMenu")
	procDestroyMenu         = windows.NewLazySystemDLL("user32.dll").NewProc("DestroyMenu")
	procGetCursorPos        = windows.NewLazySystemDLL("user32.dll").NewProc("GetCursorPos")
	procSetForegroundWindow = windows.NewLazySystemDLL("user32.dll").NewProc("SetForegroundWindow")
	procSetWindowPos        = windows.NewLazySystemDLL("user32.dll").NewProc("SetWindowPos")
	procMonitorFromPoint    = windows.NewLazySystemDLL("user32.dll").NewProc("MonitorFromPoint")
	procGetMonitorInfoW     = windows.NewLazySystemDLL("user32.dll").NewProc("GetMonitorInfoW")
	procLoadImageW          = windows.NewLazySystemDLL("user32.dll").NewProc("LoadImageW")
	procDestroyIcon         = windows.NewLazySystemDLL("user32.dll").NewProc("DestroyIcon")
	procGetModuleHandleW    = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetModuleHandleW")
	procCreateMutexW        = windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateMutexW")
	currentTrayMu           sync.Mutex
	currentTray             *helper
	hwndTopmost             = ^uintptr(0)
	hwndNotopmost           = ^uintptr(1)
)

type helper struct {
	provider          Provider
	url               string
	hwnd              windows.Handle
	iconHandle        windows.Handle
	iconPath          string
	mutexHandle       windows.Handle
	quitOnce          sync.Once
	offlineFrom       time.Time
	shutdownRequested atomic.Bool
	lastIconSignature string
}

func Run(opts Options) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	url := trimTrailingSlash(opts.URL)
	if opts.Provider != nil && url == "" {
		url = trimTrailingSlash(opts.Provider.OpenURL())
	}
	h := &helper{
		provider: opts.Provider,
		url:      url,
		iconPath: filepath.Join(os.TempDir(), fmt.Sprintf("pitchprox_tray_%d.ico", os.Getpid())),
	}
	already, err := h.acquireMutex()
	if err != nil {
		return err
	}
	if already {
		return nil
	}
	defer h.releaseMutex()

	currentTrayMu.Lock()
	currentTray = h
	currentTrayMu.Unlock()
	defer func() {
		currentTrayMu.Lock()
		if currentTray == h {
			currentTray = nil
		}
		currentTrayMu.Unlock()
	}()

	if err := h.createWindow(); err != nil {
		return err
	}
	defer h.cleanup()

	h.setOfflineIcon()
	go h.pollLoop()
	return h.messageLoop()
}

func (h *helper) acquireMutex() (bool, error) {
	name, err := windows.UTF16PtrFromString(`Local\pitchProxTrayHelper`)
	if err != nil {
		return false, err
	}
	r1, _, callErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(name)))
	if r1 == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return false, fmt.Errorf("CreateMutexW: %w", callErr)
		}
		return false, fmt.Errorf("CreateMutexW failed")
	}
	h.mutexHandle = windows.Handle(r1)
	if syscall.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		return true, nil
	}
	return false, nil
}

func (h *helper) releaseMutex() {
	if h.mutexHandle != 0 {
		_ = windows.CloseHandle(h.mutexHandle)
		h.mutexHandle = 0
	}
}

func (h *helper) createWindow() error {
	className, err := windows.UTF16PtrFromString("pitchProxTrayHelperWindow")
	if err != nil {
		return err
	}
	instance, _, callErr := procGetModuleHandleW.Call(0)
	if instance == 0 {
		return fmt.Errorf("GetModuleHandleW: %w", callErr)
	}
	wc := wndClassEx{
		CbSize:    uint32(unsafe.Sizeof(wndClassEx{})),
		WndProc:   syscall.NewCallback(windowProc),
		Instance:  windows.Handle(instance),
		ClassName: className,
	}
	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	wnd, _, callErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(className)),
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		instance,
		0,
	)
	if wnd == 0 {
		return fmt.Errorf("CreateWindowExW: %w", callErr)
	}
	h.hwnd = windows.Handle(wnd)
	return nil
}

func (h *helper) messageLoop() error {
	var m msg
	for {
		r1, _, callErr := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		switch int32(r1) {
		case -1:
			return fmt.Errorf("GetMessageW: %w", callErr)
		case 0:
			return nil
		default:
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
		}
	}
}

func windowProc(hwnd, message, wParam, lParam uintptr) uintptr {
	currentTrayMu.Lock()
	h := currentTray
	currentTrayMu.Unlock()
	if h == nil {
		ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
		return ret
	}

	switch uint32(message) {
	case trayMessage:
		event := uint32(lParam) & 0xFFFF
		switch event {
		case wmLButtonDblClk, ninKeySelect:
			h.openManagement()
			return 0
		case wmRButtonUp, wmContextMenu:
			h.showContextMenu()
			return 0
		}
	case wmCommand:
		switch uint32(wParam & 0xFFFF) {
		case menuManage:
			h.openManagement()
			return 0
		case menuPauseService:
			h.pauseService()
			return 0
		case menuResumeService:
			h.openManagement()
			return 0
		case menuExit:
			go h.requestProgramStop()
			return 0
		}
	case wmClose, wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	ret, _, _ := procDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
	return ret
}

func (h *helper) openManagement() {
	if ctl := h.serviceController(); ctl != nil && ctl.ServicePaused() {
		if err := ctl.ResumeService(); err != nil {
			return
		}
	}
	if ctl := h.webUIController(); ctl != nil {
		if err := ctl.EnableWebUI(); err != nil {
			return
		}
		if h.provider != nil {
			h.url = trimTrailingSlash(h.provider.OpenURL())
		}
	}
	if h.url != "" {
		_ = util.OpenBrowser(h.url)
	}
}

func (h *helper) showContextMenu() {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer procDestroyMenu.Call(menu)
	manageText, _ := windows.UTF16PtrFromString("Управление")
	disableWebUIText, _ := windows.UTF16PtrFromString("Отключить WebUI")
	pauseText, _ := windows.UTF16PtrFromString("Приостановить")
	resumeText, _ := windows.UTF16PtrFromString("Запустить")
	exitText, _ := windows.UTF16PtrFromString("Выйти")
	paused := false
	if ctl := h.serviceController(); ctl != nil {
		paused = ctl.ServicePaused()
	}
	if paused {
		procAppendMenuW.Call(menu, mfString, menuResumeService, uintptr(unsafe.Pointer(resumeText)))
	} else {
		procAppendMenuW.Call(menu, mfString, menuManage, uintptr(unsafe.Pointer(manageText)))
		procAppendMenuW.Call(menu, mfString, menuPauseService, uintptr(unsafe.Pointer(pauseText)))
		if ctl := h.webUIController(); ctl != nil && ctl.WebUIRunning() {
			procAppendMenuW.Call(menu, mfString, menuDisableWebUI, uintptr(unsafe.Pointer(disableWebUIText)))
		}
	}
	procAppendMenuW.Call(menu, mfString, menuExit, uintptr(unsafe.Pointer(exitText)))
	anchor, flags := h.menuAnchor()
	h.setContextMenuOwnerTopmost(true)
	defer h.setContextMenuOwnerTopmost(false)
	procSetForegroundWindow.Call(uintptr(h.hwnd))
	r1, _, _ := procTrackPopupMenu.Call(
		menu,
		flags|tpmRightButton|tpmReturnCmd|tpmNoNotify,
		uintptr(anchor.X),
		uintptr(anchor.Y),
		0,
		uintptr(h.hwnd),
		0,
	)
	procPostMessageW.Call(uintptr(h.hwnd), wmNull, 0, 0)
	switch uint32(r1) {
	case menuManage:
		h.openManagement()
	case menuPauseService:
		h.pauseService()
	case menuResumeService:
		h.openManagement()
	case menuDisableWebUI:
		h.disableWebUI()
	case menuExit:
		go h.requestProgramStop()
	}
	if h.iconHandle != 0 {
		nid := h.notifyData(h.iconHandle, "")
		procShellNotifyIconW.Call(nimSetFocus, uintptr(unsafe.Pointer(&nid)))
	}
}

func (h *helper) setContextMenuOwnerTopmost(topmost bool) {
	if h == nil || h.hwnd == 0 {
		return
	}
	insertAfter := hwndNotopmost
	if topmost {
		insertAfter = hwndTopmost
	}
	procSetWindowPos.Call(
		uintptr(h.hwnd),
		insertAfter,
		0,
		0,
		0,
		0,
		swpNoMove|swpNoSize|swpNoActivate,
	)
}

func (h *helper) webUIController() WebUIController {
	if h.provider != nil {
		ctl, _ := h.provider.(WebUIController)
		return ctl
	}
	if h.url == "" {
		return nil
	}
	return remoteWebUIController{url: h.url}
}

func (h *helper) serviceController() ServiceController {
	if h.provider != nil {
		ctl, _ := h.provider.(ServiceController)
		return ctl
	}
	if h.url == "" {
		return nil
	}
	return remoteWebUIController{url: h.url}
}

func (h *helper) disableWebUI() {
	if ctl := h.webUIController(); ctl != nil {
		_ = ctl.DisableWebUI()
	}
}

func (h *helper) pauseService() {
	if ctl := h.serviceController(); ctl != nil {
		_ = ctl.PauseService()
	}
	h.setPausedIcon()
}

func (c remoteWebUIController) WebUIRunning() bool {
	body, status, err := httpJSONRequest("GET", trimTrailingSlash(c.url)+"/api/control/webui/status", nil)
	if err != nil || status != 200 {
		return false
	}
	var payload struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	return payload.Enabled
}

func (c remoteWebUIController) EnableWebUI() error {
	return c.setWebUI(true)
}

func (c remoteWebUIController) DisableWebUI() error {
	return c.setWebUI(false)
}

func (c remoteWebUIController) setWebUI(enabled bool) error {
	action := "disable"
	if enabled {
		action = "enable"
	}
	_, status, err := httpJSONRequest("POST", trimTrailingSlash(c.url)+"/api/control/webui/"+action, []byte(`{}`))
	if err != nil {
		return err
	}
	if status != 200 && status != 204 {
		return fmt.Errorf("webui %s status: %d", action, status)
	}
	return nil
}

func (c remoteWebUIController) ServicePaused() bool {
	body, status, err := httpJSONRequest("GET", trimTrailingSlash(c.url)+"/api/control/service/status", nil)
	if err != nil || status != 200 {
		return false
	}
	var payload struct {
		Paused bool `json:"paused"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	return payload.Paused
}

func (c remoteWebUIController) PauseService() error {
	return c.setServicePaused(true)
}

func (c remoteWebUIController) ResumeService() error {
	return c.setServicePaused(false)
}

func (c remoteWebUIController) setServicePaused(paused bool) error {
	action := "resume"
	if paused {
		action = "pause"
	}
	_, status, err := httpJSONRequest("POST", trimTrailingSlash(c.url)+"/api/control/service/"+action, []byte(`{}`))
	if err != nil {
		return err
	}
	if status != 200 && status != 204 {
		return fmt.Errorf("service %s status: %d", action, status)
	}
	return nil
}

func (h *helper) menuAnchor() (point, uintptr) {
	var pt point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	anchor := pt
	flags := uintptr(tpmLeftAlign | tpmTopAlign)
	packedPt := uintptr(uint32(pt.X)) | (uintptr(uint32(pt.Y)) << 32)
	mon, _, _ := procMonitorFromPoint.Call(packedPt, monitorDefaultNear)
	if mon == 0 {
		return anchor, flags
	}
	mi := monitorInfo{CbSize: uint32(unsafe.Sizeof(monitorInfo{}))}
	r1, _, _ := procGetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi)))
	if r1 == 0 {
		return anchor, flags
	}
	const edgeMargin = 6
	if anchor.X >= mi.RcWork.Right-edgeMargin {
		anchor.X = mi.RcWork.Right - 2
		flags = (flags &^ uintptr(tpmLeftAlign)) | uintptr(tpmRightAlign)
	} else if anchor.X <= mi.RcWork.Left+edgeMargin {
		anchor.X = mi.RcWork.Left + 2
		flags = (flags &^ uintptr(tpmRightAlign)) | uintptr(tpmLeftAlign)
	}
	if anchor.Y >= mi.RcWork.Bottom-edgeMargin {
		anchor.Y = mi.RcWork.Bottom - 2
		flags = (flags &^ uintptr(tpmTopAlign)) | uintptr(tpmBottomAlign)
	} else if anchor.Y <= mi.RcWork.Top+edgeMargin {
		anchor.Y = mi.RcWork.Top + 2
		flags = (flags &^ uintptr(tpmBottomAlign)) | uintptr(tpmTopAlign)
	}
	return anchor, flags
}

func (h *helper) pollLoop() {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for range ticker.C {
		if ctl := h.serviceController(); ctl != nil && ctl.ServicePaused() {
			h.offlineFrom = time.Time{}
			h.setPausedIcon()
			continue
		}
		view, err := h.fetchTrayView()
		if err != nil {
			if h.provider != nil {
				h.setOfflineIcon()
				continue
			}
			if h.offlineFrom.IsZero() {
				h.offlineFrom = time.Now()
				h.setOfflineIcon()
				if h.shutdownRequested.Load() {
					h.quit()
					return
				}
				continue
			}
			if h.shutdownRequested.Load() || time.Since(h.offlineFrom) >= offlineExitAfter {
				h.quit()
				return
			}
			continue
		}
		h.offlineFrom = time.Time{}
		h.setTrafficIcon(view)
	}
}

func (h *helper) fetchTrayView() (monitor.TrayView, error) {
	if h.provider != nil {
		return h.provider.TrayView(trayHistorySeconds)
	}
	var view monitor.TrayView
	body, status, err := httpJSONRequest("GET", h.url+"/api/tray", nil)
	if err != nil {
		return view, err
	}
	if status != 200 {
		return view, fmt.Errorf("tray status: %d", status)
	}
	if err := json.Unmarshal(body, &view); err != nil {
		return view, err
	}
	return view, nil
}

func (h *helper) requestProgramStop() {
	h.shutdownRequested.Store(true)
	if h.provider != nil {
		_ = h.provider.RequestStop()
		h.quit()
		return
	}
	if err := h.postStop(); err != nil {
		return
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := h.fetchTrayView(); err != nil {
			h.quit()
			return
		}
		time.Sleep(350 * time.Millisecond)
	}
	h.quit()
}

func (h *helper) postStop() error {
	_, status, err := httpJSONRequest("POST", h.url+"/api/control/stop", []byte(`{}`))
	if err != nil {
		return err
	}
	if status != 200 && status != 202 && status != 204 {
		return fmt.Errorf("stop status: %d", status)
	}
	return nil
}

func (h *helper) setOfflineIcon() {
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	gray := color.NRGBA{R: 107, G: 114, B: 128, A: 255}
	for x := 2; x < 14; x++ {
		img.SetNRGBA(x, 13, gray)
	}
	for y := 3; y < 13; y++ {
		img.SetNRGBA(2, y, gray)
	}
	for i := 0; i < 10; i++ {
		img.SetNRGBA(3+i, 12-i, gray)
	}
	_ = h.updateIcon(img, "pitchProx: сервис недоступен", "offline")
}

func (h *helper) setPausedIcon() {
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	bg := color.NRGBA{R: 17, G: 24, B: 39, A: 255}
	border := color.NRGBA{R: 248, G: 113, B: 113, A: 255}
	muted := color.NRGBA{R: 156, G: 163, B: 175, A: 255}
	red := color.NRGBA{R: 220, G: 38, B: 38, A: 255}
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			switch {
			case x == 0 || x == 15 || y == 0 || y == 15:
				img.SetNRGBA(x, y, border)
			default:
				img.SetNRGBA(x, y, bg)
			}
		}
	}
	for x := 5; x <= 10; x++ {
		img.SetNRGBA(x, 4, muted)
		img.SetNRGBA(x, 11, muted)
	}
	for y := 5; y <= 10; y++ {
		img.SetNRGBA(5, y, muted)
		img.SetNRGBA(10, y, muted)
	}
	for i := 2; i <= 13; i++ {
		img.SetNRGBA(i, i, red)
		if i+1 < 16 {
			img.SetNRGBA(i+1, i, red)
		}
	}
	_ = h.updateIcon(img, "pitchProx: сервис приостановлен", "paused")
}

func (h *helper) setTrafficIcon(view monitor.TrayView) {
	history, rx, tx, peakRx, peakTx := trafficSeries(view.Traffic)
	signature := trafficSignature(history)
	if signature == h.lastIconSignature {
		return
	}
	img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	drawTrafficIconFrame(img)
	baseline := 13
	axis := color.NRGBA{R: 226, G: 232, B: 240, A: 255}
	for x := 1; x < 15; x++ {
		img.SetNRGBA(x, baseline+1, axis)
	}
	for y := 1; y < 15; y++ {
		img.SetNRGBA(1, y, axis)
	}
	rxFill := color.NRGBA{R: 20, G: 83, B: 45, A: 255}
	rxLine := color.NRGBA{R: 74, G: 222, B: 128, A: 255}
	txFill := color.NRGBA{R: 30, G: 64, B: 175, A: 255}
	txLine := color.NRGBA{R: 147, G: 197, B: 253, A: 255}
	drawRxFirst := rx >= tx
	if rx == tx {
		drawRxFirst = peakRx >= peakTx
	}
	if drawRxFirst {
		drawFilledSeries(img, history, func(p trafficPoint) int64 { return p.RxBytes }, rxFill, rxLine)
		drawFilledSeries(img, history, func(p trafficPoint) int64 { return p.TxBytes }, txFill, txLine)
	} else {
		drawFilledSeries(img, history, func(p trafficPoint) int64 { return p.TxBytes }, txFill, txLine)
		drawFilledSeries(img, history, func(p trafficPoint) int64 { return p.RxBytes }, rxFill, rxLine)
	}
	tooltip := fmt.Sprintf("pitchProx · ↓ %s/s (peak %s/s) · ↑ %s/s (peak %s/s)", formatBytes(rx), formatBytes(peakRx), formatBytes(tx), formatBytes(peakTx))
	_ = h.updateIcon(img, tooltip, signature)
}

func drawTrafficIconFrame(img *image.NRGBA) {
	bg := color.NRGBA{R: 15, G: 23, B: 42, A: 245}
	border := color.NRGBA{R: 248, G: 250, B: 252, A: 240}
	shadow := color.NRGBA{R: 2, G: 6, B: 23, A: 255}
	bounds := img.Bounds()
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			switch {
			case x == bounds.Min.X || x == bounds.Max.X-1 || y == bounds.Min.Y || y == bounds.Max.Y-1:
				img.SetNRGBA(x, y, border)
			case x == bounds.Min.X+1 || y == bounds.Max.Y-2:
				img.SetNRGBA(x, y, shadow)
			default:
				img.SetNRGBA(x, y, bg)
			}
		}
	}
}

type trafficPoint struct {
	Time    time.Time
	RxBytes int64
	TxBytes int64
}

func trafficSeries(samples []monitor.TrafficSample) ([]trafficPoint, int64, int64, int64, int64) {
	now := time.Now().UTC().Truncate(time.Second)
	history := make([]trafficPoint, 0, trayHistorySeconds)
	start := now.Add(-time.Duration(trayHistorySeconds-1) * time.Second)
	for i := trayHistorySeconds - 1; i >= 0; i-- {
		history = append(history, trafficPoint{Time: now.Add(-time.Duration(i) * time.Second)})
	}
	for _, s := range samples {
		ts := s.Time.UTC().Truncate(time.Second)
		offset := int(ts.Sub(start) / time.Second)
		if offset < 0 || offset >= len(history) {
			continue
		}
		history[offset].RxBytes += s.DownBytes
		history[offset].TxBytes += s.UpBytes
	}
	var currentRx, currentTx, peakRx, peakTx int64
	for i, p := range history {
		if p.RxBytes > peakRx {
			peakRx = p.RxBytes
		}
		if p.TxBytes > peakTx {
			peakTx = p.TxBytes
		}
		if i == len(history)-1 {
			currentRx = p.RxBytes
			currentTx = p.TxBytes
		}
	}
	return history, currentRx, currentTx, peakRx, peakTx
}

func trafficSignature(history []trafficPoint) string {
	if len(history) == 0 {
		return "empty"
	}
	var buf bytes.Buffer
	for _, p := range history {
		buf.WriteString(fmt.Sprintf("%d:%d|", p.RxBytes, p.TxBytes))
	}
	return buf.String()
}

func drawFilledSeries(img *image.NRGBA, history []trafficPoint, getter func(trafficPoint) int64, fillCol, lineCol color.NRGBA) {
	const topY = 2
	const baseY = 13
	var max int64 = trayMinScaleBytes
	for _, p := range history {
		if v := getter(p); v > max {
			max = v
		}
	}
	prevX, prevY := -1, -1
	for i, p := range history {
		x := 2 + i
		v := getter(p)
		y := baseY - int((float64(v)/float64(max))*10.0)
		if y < topY {
			y = topY
		}
		if y > baseY {
			y = baseY
		}
		for fy := y; fy <= baseY; fy++ {
			if image.Pt(x, fy).In(img.Bounds()) {
				img.SetNRGBA(x, fy, fillCol)
			}
		}
		if prevX >= 0 {
			drawLine(img, prevX, prevY, x, y, lineCol)
		}
		if image.Pt(x, y).In(img.Bounds()) {
			img.SetNRGBA(x, y, lineCol)
		}
		prevX, prevY = x, y
	}
}

func drawLine(img *image.NRGBA, x0, y0, x1, y1 int, col color.NRGBA) {
	dx := abs(x1 - x0)
	sx := -1
	if x0 < x1 {
		sx = 1
	}
	dy := -abs(y1 - y0)
	sy := -1
	if y0 < y1 {
		sy = 1
	}
	err := dx + dy
	for {
		if image.Pt(x0, y0).In(img.Bounds()) {
			img.SetNRGBA(x0, y0, col)
		}
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func (h *helper) updateIcon(img image.Image, tooltip string, signature string) error {
	if signature == h.lastIconSignature {
		return nil
	}
	icoBytes, err := encodeICO(img)
	if err != nil {
		return err
	}
	if err := os.WriteFile(h.iconPath, icoBytes, 0o644); err != nil {
		return err
	}
	pathPtr, err := windows.UTF16PtrFromString(h.iconPath)
	if err != nil {
		return err
	}
	r1, _, callErr := procLoadImageW.Call(0, uintptr(unsafe.Pointer(pathPtr)), imageIcon, 16, 16, lrLoadFromFile)
	if r1 == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return fmt.Errorf("LoadImageW: %w", callErr)
		}
		return fmt.Errorf("LoadImageW failed")
	}
	newIcon := windows.Handle(r1)
	nid := h.notifyData(newIcon, tooltip)
	msg := nimModify
	if h.iconHandle == 0 {
		msg = nimAdd
	}
	if r1, _, callErr = procShellNotifyIconW.Call(uintptr(msg), uintptr(unsafe.Pointer(&nid))); r1 == 0 {
		procDestroyIcon.Call(uintptr(newIcon))
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return fmt.Errorf("Shell_NotifyIconW: %w", callErr)
		}
		return fmt.Errorf("Shell_NotifyIconW failed")
	}
	if msg == nimAdd {
		nid.TimeoutOrVersion = notificationVer4
		procShellNotifyIconW.Call(nimSetVersion, uintptr(unsafe.Pointer(&nid)))
	}
	if h.iconHandle != 0 {
		procDestroyIcon.Call(uintptr(h.iconHandle))
	}
	h.iconHandle = newIcon
	h.lastIconSignature = signature
	return nil
}

func (h *helper) notifyData(icon windows.Handle, tooltip string) notifyIconData {
	var nid notifyIconData
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.Wnd = h.hwnd
	nid.UID = 1
	nid.Flags = nifMessage | nifIcon | nifTip
	nid.CallbackMessage = trayMessage
	nid.Icon = icon
	copyWide(nid.Tip[:], tooltip)
	return nid
}

func copyWide(dst []uint16, s string) {
	ws, _ := windows.UTF16FromString(s)
	if len(ws) > len(dst) {
		ws = ws[:len(dst)]
		ws[len(ws)-1] = 0
	}
	copy(dst, ws)
}

func encodeICO(img image.Image) ([]byte, error) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	if width <= 0 || height <= 0 || width > 256 || height > 256 {
		return nil, fmt.Errorf("unsupported icon size: %dx%d", width, height)
	}

	const (
		iconDirSize      = 6
		iconDirEntrySize = 16
		bitmapHeaderSize = 40
		bitsPerPixel     = 32
	)
	maskStride := ((width + 31) / 32) * 4
	xorBytes := width * height * 4
	maskBytes := maskStride * height
	imageBytes := bitmapHeaderSize + xorBytes + maskBytes
	out := make([]byte, 0, iconDirSize+iconDirEntrySize+imageBytes)

	out = appendUint16LE(out, 0) // reserved
	out = appendUint16LE(out, 1) // icon
	out = appendUint16LE(out, 1) // one image
	out = append(out, iconDimensionByte(width), iconDimensionByte(height), 0, 0)
	out = appendUint16LE(out, 1)
	out = appendUint16LE(out, bitsPerPixel)
	out = appendUint32LE(out, uint32(imageBytes))
	out = appendUint32LE(out, iconDirSize+iconDirEntrySize)

	out = appendUint32LE(out, bitmapHeaderSize)
	out = appendUint32LE(out, uint32(width))
	out = appendUint32LE(out, uint32(height*2)) // ICO DIB height includes XOR and AND masks.
	out = appendUint16LE(out, 1)
	out = appendUint16LE(out, bitsPerPixel)
	out = appendUint32LE(out, 0) // BI_RGB
	out = appendUint32LE(out, uint32(xorBytes+maskBytes))
	out = appendUint32LE(out, 0)
	out = appendUint32LE(out, 0)
	out = appendUint32LE(out, 0)
	out = appendUint32LE(out, 0)

	for y := bounds.Max.Y - 1; y >= bounds.Min.Y; y-- {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
			out = append(out, c.B, c.G, c.R, c.A)
		}
	}
	for i := 0; i < maskBytes; i++ {
		out = append(out, 0)
	}
	return out, nil
}

func iconDimensionByte(v int) byte {
	if v == 256 {
		return 0
	}
	return byte(v)
}

func appendUint16LE(dst []byte, v uint16) []byte {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], v)
	return append(dst, buf[:]...)
}

func appendUint32LE(dst []byte, v uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return append(dst, buf[:]...)
}

func (h *helper) quit() {
	h.quitOnce.Do(func() {
		procPostMessageW.Call(uintptr(h.hwnd), wmClose, 0, 0)
	})
}

func (h *helper) cleanup() {
	if h.hwnd != 0 {
		nid := h.notifyData(h.iconHandle, "")
		procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	}
	if h.iconHandle != 0 {
		procDestroyIcon.Call(uintptr(h.iconHandle))
		h.iconHandle = 0
	}
	_ = os.Remove(h.iconPath)
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func formatBytes(v int64) string {
	units := []string{"B", "KB", "MB", "GB"}
	fv := float64(v)
	idx := 0
	for fv >= 1024 && idx < len(units)-1 {
		fv /= 1024
		idx++
	}
	if idx == 0 {
		return fmt.Sprintf("%d %s", v, units[idx])
	}
	if fv >= 100 {
		return fmt.Sprintf("%.0f %s", fv, units[idx])
	}
	return fmt.Sprintf("%.1f %s", fv, units[idx])
}

func trimTrailingSlash(url string) string {
	for len(url) > 0 && url[len(url)-1] == '/' {
		url = url[:len(url)-1]
	}
	return url
}

func httpJSONRequest(method, rawURL string, body []byte) ([]byte, int, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, err
	}
	host := u.Host
	if host == "" {
		return nil, 0, fmt.Errorf("missing host")
	}
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "80")
	}
	conn, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	target := u.EscapedPath()
	if target == "" {
		target = "/"
	}
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}

	bw := bufio.NewWriter(conn)
	if _, err := fmt.Fprintf(bw, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", method, target, u.Host); err != nil {
		return nil, 0, err
	}
	if len(body) > 0 {
		if _, err := fmt.Fprintf(bw, "Content-Type: application/json\r\nContent-Length: %d\r\n", len(body)); err != nil {
			return nil, 0, err
		}
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return nil, 0, err
	}
	if len(body) > 0 {
		if _, err := bw.Write(body); err != nil {
			return nil, 0, err
		}
	}
	if err := bw.Flush(); err != nil {
		return nil, 0, err
	}
	return readHTTPResponse(bufio.NewReader(conn))
}

func readHTTPResponse(br *bufio.Reader) ([]byte, int, error) {
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, 0, err
	}
	parts := bytes.Fields([]byte(statusLine))
	if len(parts) < 2 {
		return nil, 0, fmt.Errorf("invalid response status")
	}
	status, err := strconv.Atoi(string(parts[1]))
	if err != nil {
		return nil, 0, err
	}

	headers := map[string]string{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, 0, err
		}
		line = trimHTTPLine(line)
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, 0, fmt.Errorf("invalid response header")
		}
		headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}

	if strings.Contains(strings.ToLower(headers["transfer-encoding"]), "chunked") {
		body, err := readChunkedBody(br)
		return body, status, err
	}
	if lengthText := headers["content-length"]; lengthText != "" {
		n, err := strconv.Atoi(lengthText)
		if err != nil || n < 0 {
			return nil, 0, fmt.Errorf("invalid content length")
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, 0, err
		}
		return body, status, nil
	}
	body, err := io.ReadAll(br)
	return body, status, err
}

func readChunkedBody(br *bufio.Reader) ([]byte, error) {
	var body bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = trimHTTPLine(line)
		sizeText := line
		if idx := strings.IndexByte(sizeText, ';'); idx >= 0 {
			sizeText = sizeText[:idx]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeText), 16, 64)
		if err != nil {
			return nil, err
		}
		if size == 0 {
			for {
				trailer, err := br.ReadString('\n')
				if err != nil {
					return nil, err
				}
				if trimHTTPLine(trailer) == "" {
					return body.Bytes(), nil
				}
			}
		}
		if _, err := io.CopyN(&body, br, size); err != nil {
			return nil, err
		}
		if _, err := br.ReadString('\n'); err != nil {
			return nil, err
		}
	}
}

func trimHTTPLine(v string) string {
	return strings.TrimRight(v, "\r\n")
}
