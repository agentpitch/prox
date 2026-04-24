package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/openai/pitchprox/internal/app"
	"github.com/openai/pitchprox/internal/config"
	"github.com/openai/pitchprox/internal/monitor"
	svcwrap "github.com/openai/pitchprox/internal/service"
	"github.com/openai/pitchprox/internal/trayapp"
	"github.com/openai/pitchprox/internal/util"
)

const (
	serviceName        = "pitchProx"
	serviceDisplayName = "pitchProx Transparent Proxy"
	serviceDescription = "Local WebUI + WinDivert transparent proxy service"
)

func main() {
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if cmd == "run" {
		util.HideConsoleIfOwn()
	}

	switch cmd {
	case "run":
		if !util.IsElevated() {
			must(util.RelaunchSelfElevated(os.Args[1:]))
			return
		}
		must(runForeground())
	case "service":
		must(util.RequireElevation("service"))
		must(runService())
	case "install":
		must(util.RequireElevation("install"))
		exe, err := os.Executable()
		must(err)
		must(svcwrap.Install(serviceName, serviceDisplayName, serviceDescription, exe))
		fmt.Println("service installed")
	case "uninstall":
		must(util.RequireElevation("uninstall"))
		must(svcwrap.Uninstall(serviceName))
		fmt.Println("service uninstalled")
	case "start":
		must(util.RequireElevation("start"))
		must(svcwrap.Start(serviceName))
		fmt.Println("service started")
	case "stop":
		must(util.RequireElevation("stop"))
		must(svcwrap.Stop(serviceName))
		fmt.Println("service stopped")
	case "open":
		st, err := config.NewStore(util.ConfigPath())
		must(err)
		must(util.OpenBrowser("http://" + st.Get().HTTP.Listen))
	case "tray":
		must(runTray())
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

type programTrayProvider struct{ prog *app.Program }

func (p programTrayProvider) TrayView(seconds int) (monitor.TrayView, error) {
	return p.prog.Runtime().TrayView(seconds), nil
}
func (p programTrayProvider) OpenURL() string { return p.prog.Runtime().WebUIURL() }
func (p programTrayProvider) WebUIRunning() bool {
	return p.prog.WebUIRunning()
}
func (p programTrayProvider) EnableWebUI() error {
	return p.prog.EnableWebUI()
}
func (p programTrayProvider) DisableWebUI() error {
	return p.prog.DisableWebUI()
}
func (p programTrayProvider) RequestStop() error {
	p.prog.RequestStop()
	return nil
}

func runForeground() error {
	prog, err := app.NewProgram(util.ConfigPath(), util.HistoryPath())
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := prog.Start(ctx); err != nil {
		return err
	}
	if os.Getenv("PITCHPROX_DISABLE_TRAY") != "1" && os.Getenv("MYPROX_DISABLE_TRAY") != "1" {
		go func() {
			if err := trayapp.Run(trayapp.Options{Provider: programTrayProvider{prog: prog}}); err != nil {
				prog.Runtime().Monitor().AddLog("warn", "tray: %v", err)
			}
		}()
	}
	select {
	case <-ctx.Done():
	case <-prog.StopRequested():
	}
	return prog.Stop()
}

func runService() error {
	prog, err := app.NewProgram(util.ConfigPath(), util.HistoryPath())
	if err != nil {
		return err
	}
	return svcwrap.RunService(serviceName, prog)
}

func runTray() error {
	url := ""
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--url" && i+1 < len(os.Args) {
			url = os.Args[i+1]
			i++
		}
	}
	if url == "" {
		st, err := config.NewStore(util.ConfigPath())
		if err != nil {
			return err
		}
		url = "http://" + st.Get().HTTP.Listen
	}
	return trayapp.Run(trayapp.Options{URL: url})
}

func usage() {
	fmt.Println(`pitchProx commands:
  run         run desktop mode (single process: runtime + WebUI + tray)
  service     run under Windows Service Manager (headless)
  install     install Windows service
  uninstall   uninstall Windows service
  start       start Windows service
  stop        stop Windows service
  open        open localhost WebUI
  tray        run tray loop only (diagnostic mode against URL)`)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
