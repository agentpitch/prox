//go:build !windows

package trayapp

import "github.com/openai/pitchprox/internal/monitor"

type Provider interface {
	TrayView(seconds int) (monitor.TrayView, error)
	OpenURL() string
	RequestStop() error
}

type Options struct {
	URL      string
	Provider Provider
}

func Run(opts Options) error { return nil }
