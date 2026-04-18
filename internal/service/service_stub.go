//go:build !windows

package service

import (
	"context"
	"fmt"
)

type Runner interface {
	Start(ctx context.Context) error
	Stop() error
	StopRequested() <-chan struct{}
}

func RunService(name string, r Runner) error                       { return fmt.Errorf("windows only") }
func Install(name, displayName, description, exePath string) error { return fmt.Errorf("windows only") }
func Uninstall(name string) error                                  { return fmt.Errorf("windows only") }
func Start(name string) error                                      { return fmt.Errorf("windows only") }
func Stop(name string) error                                       { return fmt.Errorf("windows only") }
