package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagerCheckSelectsLatestStableAndComparison(t *testing.T) {
	releases := []Release{
		{Version: "v0.41", Installable: true},
		{Version: "v9.0-rc.1", Prerelease: true, Installable: true},
		{Version: "not-a-version"},
		{Version: "v0.44", Installable: true},
		{Version: "v0.43", Installable: true},
	}
	tests := []struct {
		name            string
		current         string
		comparisonKnown bool
		updateAvailable bool
	}{
		{name: "older stable", current: "v0.42", comparisonKnown: true, updateAvailable: true},
		{name: "same stable", current: "v0.44", comparisonKnown: true, updateAvailable: false},
		{name: "newer stable", current: "v0.45", comparisonKnown: true, updateAvailable: false},
		{name: "development build", current: "dev-1a2b3c4", comparisonKnown: false, updateAvailable: false},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			source := &managerTestSource{releases: releases}
			manager, _ := newManagerTestFixture(t, test.current, source, nil, nil)

			result, err := manager.Check(context.Background())
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if result.CurrentVersion != test.current {
				t.Fatalf("CurrentVersion = %q, want %q", result.CurrentVersion, test.current)
			}
			if result.LatestVersion != "v0.44" {
				t.Fatalf("LatestVersion = %q, want v0.44", result.LatestVersion)
			}
			if result.ComparisonKnown != test.comparisonKnown {
				t.Fatalf("ComparisonKnown = %v, want %v", result.ComparisonKnown, test.comparisonKnown)
			}
			if result.UpdateAvailable != test.updateAvailable {
				t.Fatalf("UpdateAvailable = %v, want %v", result.UpdateAvailable, test.updateAvailable)
			}
			if len(result.Releases) != len(releases) {
				t.Fatalf("len(Releases) = %d, want %d", len(result.Releases), len(releases))
			}
			if calls, _ := source.callCounts(); calls != 1 {
				t.Fatalf("ListReleases calls = %d, want 1", calls)
			}
			status := manager.Status()
			if status.Phase != PhaseIdle || status.Busy {
				t.Fatalf("status after Check = %#v, want idle and not busy", status)
			}
		})
	}
}

func TestManagerCheckFindsStableReleaseBeyondVisibleFive(t *testing.T) {
	releases := []Release{
		{Version: "v0.50-rc.5", Prerelease: true, Installable: true},
		{Version: "v0.50-rc.4", Prerelease: true, Installable: true},
		{Version: "v0.50-rc.3", Prerelease: true, Installable: true},
		{Version: "v0.50-rc.2", Prerelease: true, Installable: true},
		{Version: "v0.50-rc.1", Prerelease: true, Installable: true},
		{Version: "v0.49", Installable: true},
	}
	manager, _ := newManagerTestFixture(t, "v0.48", &managerTestSource{releases: releases}, nil, nil)

	result, err := manager.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if len(result.Releases) != maxVisibleReleases {
		t.Fatalf("len(Releases) = %d, want %d", len(result.Releases), maxVisibleReleases)
	}
	if result.LatestVersion != "v0.49" || !result.ComparisonKnown || !result.UpdateAvailable {
		t.Fatalf("stable comparison = %#v, want available v0.49 update", result)
	}
	for _, release := range result.Releases {
		if release.Version == "v0.49" {
			t.Fatal("stable comparison candidate leaked into the five-release UI list")
		}
	}
}

func TestManagerInstallUsesExactCachedReleaseAndIsSingleFlight(t *testing.T) {
	stageStarted := make(chan Release, 1)
	releaseStage := make(chan struct{})
	stageFailure := errors.New("stop staged download")
	wanted := Release{Version: "v0.43", Size: 4300, Installable: true, Verification: "manifest", id: 43}
	other := Release{Version: "v0.44", Size: 4400, Installable: true, Verification: "manifest", id: 44}
	source := &managerTestSource{releases: []Release{other, wanted}}
	source.stage = func(ctx context.Context, release Release, _ string, _ func(int64, int64)) error {
		stageStarted <- release
		select {
		case <-releaseStage:
			return stageFailure
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	manager, _ := newManagerTestFixture(t, "v0.42", source, nil, nil)
	if _, err := manager.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}

	if _, err := manager.StartInstall(wanted.Version); err != nil {
		t.Fatalf("StartInstall: %v", err)
	}
	var staged Release
	select {
	case staged = <-stageStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("Stage was not called")
	}
	if staged.Version != wanted.Version || staged.id != wanted.id || staged.Size != wanted.Size {
		t.Fatalf("Stage release = %#v, want exact cached release %#v", staged, wanted)
	}
	if _, err := manager.StartInstall(other.Version); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second StartInstall error = %v, want single-flight rejection", err)
	}
	if _, err := manager.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("concurrent Check error = %v, want single-flight rejection", err)
	}
	close(releaseStage)
	manager.wg.Wait()

	listCalls, stageCalls := source.callCounts()
	if listCalls != 1 {
		t.Fatalf("ListReleases calls = %d, want cached install with only the original Check", listCalls)
	}
	if stageCalls != 1 {
		t.Fatalf("Stage calls = %d, want 1", stageCalls)
	}
	status := manager.Status()
	if status.Phase != PhaseFailed || status.Error != stageFailure.Error() {
		t.Fatalf("status after released Stage = %#v, want stage failure", status)
	}
}

func TestManagerStageFailureCleansFilesAndPersistsStatus(t *testing.T) {
	stageFailure := errors.New("staging failed deliberately")
	var expectedStage string
	var handoffCalls, stopCalls atomic.Int32
	source := &managerTestSource{
		releases: []Release{{Version: "v0.43", Size: 100, Installable: true, Verification: "manifest"}},
	}
	source.stage = func(_ context.Context, _ Release, destination string, progress func(int64, int64)) error {
		if destination != expectedStage {
			return fmt.Errorf("Stage destination = %q, want %q", destination, expectedStage)
		}
		if err := os.WriteFile(destination, []byte("partial-stage"), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(destination+".part", []byte("partial-download"), 0o600); err != nil {
			return err
		}
		progress(25, 100)
		return stageFailure
	}
	manager, directory := newManagerTestFixture(t, "v0.42", source, func(HandoffPlan) error {
		handoffCalls.Add(1)
		return nil
	}, func() {
		stopCalls.Add(1)
	})
	paths := updatePaths(directory)
	expectedStage = paths.Stage
	if _, err := manager.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, err := manager.StartInstall("v0.43"); err != nil {
		t.Fatalf("StartInstall: %v", err)
	}
	manager.wg.Wait()

	for _, path := range []string{paths.Stage, paths.Stage + ".part"} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed transaction file %s remains: %v", filepath.Base(path), err)
		}
	}
	status := manager.Status()
	if status.Phase != PhaseFailed || status.Busy || status.Version != "v0.43" || status.Error != stageFailure.Error() {
		t.Fatalf("failure status = %#v", status)
	}
	var persisted Status
	if err := readBoundedJSON(paths.State, &persisted, 64<<10); err != nil {
		t.Fatalf("read persisted failure: %v", err)
	}
	if persisted.Phase != PhaseFailed || persisted.Error != stageFailure.Error() || persisted.Version != "v0.43" {
		t.Fatalf("persisted failure = %#v", persisted)
	}
	if handoffCalls.Load() != 0 || stopCalls.Load() != 0 {
		t.Fatalf("handoff/stop calls after Stage failure = %d/%d, want 0/0", handoffCalls.Load(), stopCalls.Load())
	}
}

func TestManagerSuccessfulInstallBuildsHandoffPlanAndStops(t *testing.T) {
	newExecutable := []byte("verified replacement executable")
	release := Release{Version: "v0.43", Size: int64(len(newExecutable)), Installable: true, Verification: "legacy", id: 43}
	source := &managerTestSource{releases: []Release{release}}
	source.stage = func(_ context.Context, got Release, destination string, progress func(int64, int64)) error {
		if got.Version != release.Version || got.id != release.id {
			return fmt.Errorf("Stage got release %#v, want %#v", got, release)
		}
		if err := os.WriteFile(destination, newExecutable, 0o700); err != nil {
			return err
		}
		progress(int64(len(newExecutable)), int64(len(newExecutable)))
		return nil
	}
	plans := make(chan HandoffPlan, 1)
	var handoffReturned atomic.Bool
	var stopCalls atomic.Int32
	var stopBeforeHandoff atomic.Bool
	manager, directory := newManagerTestFixture(t, "v0.42", source, func(plan HandoffPlan) error {
		plans <- plan
		handoffReturned.Store(true)
		return nil
	}, func() {
		if !handoffReturned.Load() {
			stopBeforeHandoff.Store(true)
		}
		stopCalls.Add(1)
	})
	manager.mode = ModeService
	manager.serviceName = "pitchProx-test-service"
	manager.listenAddress = "127.0.0.1:18080"
	oldHash, err := hashFile(manager.executablePath)
	if err != nil {
		t.Fatal(err)
	}
	startedAt := time.Now().UTC()
	if _, err := manager.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, err := manager.StartInstall(release.Version); err != nil {
		t.Fatalf("StartInstall: %v", err)
	}
	manager.wg.Wait()

	var plan HandoffPlan
	select {
	case plan = <-plans:
	default:
		t.Fatal("handoff was not called")
	}
	paths := updatePaths(directory)
	if plan.Format != handoffPlanFormat || plan.FormatVersion != 2 {
		t.Fatalf("plan format = %q/%d", plan.Format, plan.FormatVersion)
	}
	if plan.Mode != ModeService || plan.ServiceName != manager.serviceName || plan.ListenAddress != manager.listenAddress {
		t.Fatalf("plan runtime identity = %#v", plan)
	}
	if plan.TargetPath != manager.executablePath || plan.StagePath != paths.Stage || plan.BackupPath != paths.Backup || plan.PlanPath != paths.Plan || plan.ReadyPath != paths.Ready || plan.ProceedPath != paths.Proceed || plan.StatePath != paths.State {
		t.Fatalf("plan paths = %#v, want paths rooted at %q", plan, directory)
	}
	if plan.ParentPID != os.Getpid() {
		t.Fatalf("ParentPID = %d, want %d", plan.ParentPID, os.Getpid())
	}
	if runtime.GOOS == "windows" && plan.ParentStarted == 0 {
		t.Fatal("ParentStarted is zero on Windows")
	}
	if plan.Version != release.Version || !plan.LegacyHealth {
		t.Fatalf("plan release identity = %#v", plan)
	}
	if plan.OldSHA256 != oldHash || plan.NewSHA256 != managerSHA256(newExecutable) {
		t.Fatalf("plan hashes = old %q new %q", plan.OldSHA256, plan.NewSHA256)
	}
	if len(plan.UpdateToken) != 64 {
		t.Fatalf("UpdateToken length = %d, want 64", len(plan.UpdateToken))
	}
	if _, err := hex.DecodeString(plan.UpdateToken); err != nil {
		t.Fatalf("UpdateToken is not hexadecimal: %v", err)
	}
	if plan.CreatedAt.Before(startedAt) || plan.CreatedAt.After(time.Now().UTC().Add(time.Second)) {
		t.Fatalf("CreatedAt = %s, want current install time", plan.CreatedAt)
	}
	if stopCalls.Load() != 1 || stopBeforeHandoff.Load() {
		t.Fatalf("stop callback count/before-handoff = %d/%v", stopCalls.Load(), stopBeforeHandoff.Load())
	}

	var persistedPlan HandoffPlan
	if err := readBoundedJSON(paths.Plan, &persistedPlan, 64<<10); err != nil {
		t.Fatalf("read persisted plan: %v", err)
	}
	if persistedPlan.UpdateToken != plan.UpdateToken || persistedPlan.OldSHA256 != plan.OldSHA256 || persistedPlan.NewSHA256 != plan.NewSHA256 || persistedPlan.StagePath != plan.StagePath {
		t.Fatalf("persisted plan = %#v, want handoff plan %#v", persistedPlan, plan)
	}
	var persistedStatus Status
	if err := readBoundedJSON(paths.State, &persistedStatus, 64<<10); err != nil {
		t.Fatalf("read persisted status: %v", err)
	}
	if persistedStatus.Phase != PhaseRestarting || !persistedStatus.Busy || persistedStatus.Version != release.Version {
		t.Fatalf("persisted restarting status = %#v", persistedStatus)
	}
	status := manager.Status()
	if status.Phase != PhaseRestarting || !status.Busy || status.DownloadedBytes != release.Size || status.TotalBytes != release.Size {
		t.Fatalf("manager status after handoff = %#v", status)
	}
}

func TestManagerPossiblyCommittedHandoffStaysRestarting(t *testing.T) {
	newExecutable := []byte("verified replacement executable")
	release := Release{Version: "v0.43", Size: int64(len(newExecutable)), Installable: true, Verification: "manifest", id: 43}
	source := &managerTestSource{releases: []Release{release}}
	source.stage = func(_ context.Context, _ Release, destination string, _ func(int64, int64)) error {
		return os.WriteFile(destination, newExecutable, 0o700)
	}
	var stopCalls atomic.Int32
	manager, directory := newManagerTestFixture(t, "v0.42", source, func(HandoffPlan) error { return nil }, func() {
		stopCalls.Add(1)
	})
	manager.customHandoff = false
	manager.handoff = func(_ HandoffPlan, releaseLock func() (bool, error)) error {
		released, err := releaseLock()
		if err != nil || !released {
			return fmt.Errorf("release update lock: %w", err)
		}
		return fmt.Errorf("%w: simulated missing helper acknowledgement", errHandoffPossiblyCommitted)
	}

	if _, err := manager.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, err := manager.StartInstall(release.Version); err != nil {
		t.Fatalf("StartInstall: %v", err)
	}
	manager.wg.Wait()

	manager.mu.Lock()
	status := manager.status
	manager.mu.Unlock()
	if status.Phase != PhaseRestarting || !status.Busy || status.Version != release.Version {
		t.Fatalf("possibly committed status = %#v, want the non-terminal restarting state", status)
	}
	if stopCalls.Load() != 0 {
		t.Fatalf("stop callback calls = %d, want 0 until helper ownership is certain", stopCalls.Load())
	}
	var persisted Status
	if err := readBoundedJSON(filepath.Join(directory, stateFileName), &persisted, 64<<10); err != nil {
		t.Fatalf("read persisted restarting status: %v", err)
	}
	if persisted.Phase != PhaseRestarting || !persisted.Busy || persisted.TransactionID == "" {
		t.Fatalf("persisted possibly committed status = %#v", persisted)
	}
}

func TestManagerCloseCancelsActiveInstall(t *testing.T) {
	stageStarted := make(chan string, 1)
	stageCanceled := make(chan struct{}, 1)
	var handoffCalls, stopCalls atomic.Int32
	source := &managerTestSource{
		releases: []Release{{Version: "v0.43", Size: 100, Installable: true, Verification: "manifest"}},
	}
	source.stage = func(ctx context.Context, _ Release, destination string, _ func(int64, int64)) error {
		if err := os.WriteFile(destination+".part", []byte("in progress"), 0o600); err != nil {
			return err
		}
		stageStarted <- destination
		<-ctx.Done()
		stageCanceled <- struct{}{}
		return ctx.Err()
	}
	manager, _ := newManagerTestFixture(t, "v0.42", source, func(HandoffPlan) error {
		handoffCalls.Add(1)
		return nil
	}, func() {
		stopCalls.Add(1)
	})
	if _, err := manager.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, err := manager.StartInstall("v0.43"); err != nil {
		t.Fatalf("StartInstall: %v", err)
	}
	var stagePath string
	select {
	case stagePath = <-stageStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("Stage did not start")
	}
	closed := make(chan struct{})
	go func() {
		manager.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not cancel and join the active install")
	}
	select {
	case <-stageCanceled:
	default:
		t.Fatal("Stage did not observe context cancellation")
	}
	if _, err := os.Stat(stagePath + ".part"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial stage remains after Close: %v", err)
	}
	status := manager.Status()
	if status.Phase != PhaseFailed || !strings.Contains(strings.ToLower(status.Error), "canceled") {
		t.Fatalf("status after Close = %#v, want cancellation failure", status)
	}
	if _, err := manager.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Check after Close error = %v, want closed", err)
	}
	if _, err := manager.StartInstall("v0.43"); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("StartInstall after Close error = %v, want closed", err)
	}
	if handoffCalls.Load() != 0 || stopCalls.Load() != 0 {
		t.Fatalf("handoff/stop calls after cancellation = %d/%d, want 0/0", handoffCalls.Load(), stopCalls.Load())
	}
}

func TestManagerLoadsPersistedStatusAndHealthToken(t *testing.T) {
	directory := t.TempDir()
	executablePath := filepath.Join(directory, "pitchProx.exe")
	if err := os.WriteFile(executablePath, []byte("current executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(executablePath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	persisted := Status{Phase: PhaseSucceeded, Busy: true, Version: "v0.43", Message: "installed", UpdatedAt: now}
	mustWriteManagerJSON(t, filepath.Join(directory, stateFileName), persisted)
	token := strings.Repeat("a", 64)
	plan := HandoffPlan{
		Format:        handoffPlanFormat,
		FormatVersion: 2,
		TargetPath:    absolute,
		Version:       "v0.43",
		UpdateToken:   token,
		TransactionID: transactionIDForToken(token),
		CreatedAt:     now.Add(-time.Minute),
	}
	planPath := filepath.Join(directory, planFileName)
	mustWriteManagerJSON(t, planPath, plan)
	manager, err := NewManager(ManagerOptions{
		CurrentVersion: "v0.43",
		Mode:           ModeDesktop,
		ExecutablePath: executablePath,
		Source:         &managerTestSource{},
		StopFunc:       func() {},
		Handoff:        func(HandoffPlan) error { return nil },
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(manager.Close)

	status := manager.Status()
	if status.Phase != PhaseSucceeded || status.Busy || status.Version != "v0.43" || status.Message != "installed" {
		t.Fatalf("loaded status = %#v", status)
	}
	if got := manager.HealthToken(); got != token {
		t.Fatalf("HealthToken = %q, want %q", got, token)
	}
	if err := os.Remove(planPath); err != nil {
		t.Fatal(err)
	}
	if got := manager.HealthToken(); got != "" {
		t.Fatalf("HealthToken after plan removal = %q, want empty", got)
	}
}

func TestManagerSameVersionInstallIsNoOp(t *testing.T) {
	source := &managerTestSource{releases: []Release{{Version: "v0.43", Installable: true}}}
	var handoffCalls, stopCalls atomic.Int32
	manager, directory := newManagerTestFixture(t, "v0.43.0", source, func(HandoffPlan) error {
		handoffCalls.Add(1)
		return nil
	}, func() { stopCalls.Add(1) })

	status, err := manager.StartInstall("v0.43")
	if err != nil {
		t.Fatalf("StartInstall current version: %v", err)
	}
	if status.Phase != PhaseSucceeded || status.Busy || !strings.Contains(status.Message, "уже установлена") {
		t.Fatalf("same-version status = %#v", status)
	}
	listCalls, stageCalls := source.callCounts()
	if listCalls != 0 || stageCalls != 0 || handoffCalls.Load() != 0 || stopCalls.Load() != 0 {
		t.Fatalf("same-version side effects: list=%d stage=%d handoff=%d stop=%d", listCalls, stageCalls, handoffCalls.Load(), stopCalls.Load())
	}
	if _, err := os.Stat(filepath.Join(directory, planFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("same-version install created a plan: %v", err)
	}
}

func TestManagerReadsLatestListenAddressForHandoff(t *testing.T) {
	newExecutable := []byte("new executable")
	source := &managerTestSource{releases: []Release{{Version: "v0.44", Size: int64(len(newExecutable)), Installable: true, Verification: "manifest"}}}
	source.stage = func(_ context.Context, _ Release, destination string, _ func(int64, int64)) error {
		return os.WriteFile(destination, newExecutable, 0o700)
	}
	plans := make(chan HandoffPlan, 1)
	manager, _ := newManagerTestFixture(t, "v0.43", source, func(plan HandoffPlan) error {
		plans <- plan
		return nil
	}, func() {})
	currentAddress := "127.0.0.1:18080"
	manager.listenProvider = func() string { return currentAddress }
	if _, err := manager.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	currentAddress = "127.0.0.1:19090"
	if _, err := manager.StartInstall("v0.44"); err != nil {
		t.Fatal(err)
	}
	manager.wg.Wait()
	select {
	case plan := <-plans:
		if plan.ListenAddress != currentAddress {
			t.Fatalf("ListenAddress = %q, want latest %q", plan.ListenAddress, currentAddress)
		}
	default:
		t.Fatal("handoff plan was not captured")
	}
}

func TestManagerRequiresRestartingStateBeforeHandoff(t *testing.T) {
	newExecutable := []byte("new executable")
	source := &managerTestSource{releases: []Release{{Version: "v0.44", Size: int64(len(newExecutable)), Installable: true, Verification: "manifest"}}}
	source.stage = func(_ context.Context, _ Release, destination string, _ func(int64, int64)) error {
		return os.WriteFile(destination, newExecutable, 0o700)
	}
	var handoffCalls, stopCalls atomic.Int32
	manager, directory := newManagerTestFixture(t, "v0.43", source, func(HandoffPlan) error {
		handoffCalls.Add(1)
		return nil
	}, func() { stopCalls.Add(1) })
	paths := updatePaths(directory)
	if err := os.Mkdir(paths.State, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.StartInstall("v0.44"); err != nil {
		t.Fatal(err)
	}
	manager.wg.Wait()
	if handoffCalls.Load() != 0 || stopCalls.Load() != 0 {
		t.Fatalf("handoff=%d stop=%d, want no handoff after state write failure", handoffCalls.Load(), stopCalls.Load())
	}
	if status := manager.Status(); status.Phase != PhaseFailed || !strings.Contains(status.Error, "record update transaction") {
		t.Fatalf("status = %#v", status)
	}
	for _, path := range []string{paths.Plan, paths.Stage} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("transaction artifact remains at %s: %v", path, err)
		}
	}
}

func TestReconcileRequiresMatchingCompletedTransaction(t *testing.T) {
	for _, test := range []struct {
		name          string
		transactionID string
		wantClean     bool
	}{
		{name: "matching commit", wantClean: true},
		{name: "stale commit", transactionID: strings.Repeat("f", 64), wantClean: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			oldContent := []byte("old executable")
			newContent := []byte("new executable")
			target := filepath.Join(directory, "pitchProx.exe")
			if err := os.WriteFile(target, newContent, 0o700); err != nil {
				t.Fatal(err)
			}
			paths := updatePaths(directory)
			for path, content := range map[string][]byte{
				paths.Backup: oldContent, paths.Recovery: oldContent, paths.Stage: newContent,
			} {
				if err := os.WriteFile(path, content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			token := strings.Repeat("a", 64)
			transactionID := transactionIDForToken(token)
			createdAt := time.Now().UTC().Add(-time.Second)
			plan := HandoffPlan{
				Format: handoffPlanFormat, FormatVersion: 2, TargetPath: target,
				StagePath: paths.Stage, BackupPath: paths.Backup, RecoveryPath: paths.Recovery,
				PlanPath: paths.Plan, ReadyPath: paths.Ready, ProceedPath: paths.Proceed, StatePath: paths.State,
				Version: "v0.44", OldVersion: "v0.43", OldSHA256: managerSHA256(oldContent), NewSHA256: managerSHA256(newContent),
				UpdateToken: token, TransactionID: transactionID, CreatedAt: createdAt,
			}
			mustWriteManagerJSON(t, paths.Plan, plan)
			persistedTransactionID := test.transactionID
			if persistedTransactionID == "" {
				persistedTransactionID = transactionID
			}
			mustWriteManagerJSON(t, paths.State, Status{
				Phase: PhaseSucceeded, Version: plan.Version, TransactionID: persistedTransactionID, UpdatedAt: createdAt.Add(time.Second),
			})
			manager, err := NewManager(ManagerOptions{
				CurrentVersion: "v0.44", Mode: ModeDesktop, ListenAddress: "127.0.0.1:18080",
				ExecutablePath: target, Source: &managerTestSource{}, StopFunc: func() {},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(manager.Close)
			manager.reconcileTransaction(true)
			_, planErr := os.Stat(paths.Plan)
			if test.wantClean {
				if !errors.Is(planErr, os.ErrNotExist) {
					t.Fatalf("committed transaction plan remains: %v", planErr)
				}
				if status := manager.Status(); status.Phase != PhaseSucceeded {
					t.Fatalf("committed status = %#v", status)
				}
			} else {
				if planErr != nil {
					t.Fatalf("unconfirmed transaction plan was removed: %v", planErr)
				}
				if _, err := os.Stat(paths.Backup); err != nil {
					t.Fatalf("rollback backup was removed: %v", err)
				}
				if status := manager.Status(); status.Phase != PhaseFailed || !strings.Contains(status.Error, "не подтвердил") {
					t.Fatalf("unconfirmed status = %#v", status)
				}
				if _, err := manager.Check(context.Background()); err != nil {
					t.Fatalf("release check during quarantined transaction: %v", err)
				}
				if status := manager.Status(); status.Phase != PhaseFailed || !strings.Contains(status.Error, "не подтвердил") {
					t.Fatalf("release check hid quarantined status: %#v", status)
				}
				if _, err := manager.StartInstall(plan.Version); err == nil || !strings.Contains(err.Error(), "unfinished update transaction") {
					t.Fatalf("install with quarantined plan error = %v", err)
				}
				beforeStatus, err := os.Stat(paths.State)
				if err != nil {
					t.Fatal(err)
				}
				time.Sleep(20 * time.Millisecond)
				_ = manager.Status()
				afterStatus, err := os.Stat(paths.State)
				if err != nil {
					t.Fatal(err)
				}
				if !beforeStatus.ModTime().Equal(afterStatus.ModTime()) {
					t.Fatalf("memoized Status rewrote quarantined state: before=%s after=%s", beforeStatus.ModTime(), afterStatus.ModTime())
				}
			}
		})
	}
}

func TestCheckPreservesSuccessfulCleanupWarningWhilePlanRemains(t *testing.T) {
	directory := t.TempDir()
	oldContent := []byte("old executable")
	newContent := []byte("new executable")
	target := filepath.Join(directory, executableName)
	if err := os.WriteFile(target, newContent, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := updatePaths(directory)
	token := strings.Repeat("a", 64)
	createdAt := time.Now().UTC().Add(-time.Second)
	plan := HandoffPlan{
		Format: handoffPlanFormat, FormatVersion: 2, TargetPath: target,
		StagePath: paths.Stage, BackupPath: paths.Backup, RecoveryPath: paths.Recovery,
		PlanPath: paths.Plan, ReadyPath: paths.Ready, ProceedPath: paths.Proceed, StatePath: paths.State,
		Version: "v0.44", OldVersion: "v0.43", OldSHA256: managerSHA256(oldContent), NewSHA256: managerSHA256(newContent),
		UpdateToken: token, TransactionID: transactionIDForToken(token), CreatedAt: createdAt,
	}
	mustWriteManagerJSON(t, paths.Plan, plan)
	mustWriteManagerJSON(t, paths.State, Status{
		Phase: PhaseSucceeded, Version: plan.Version, TransactionID: plan.TransactionID, UpdatedAt: createdAt.Add(time.Second),
	})
	if err := os.Mkdir(paths.Ready, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.Ready, "keep"), []byte("busy"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := &managerTestSource{releases: []Release{{Version: "v0.45", Installable: true}}}
	manager, err := NewManager(ManagerOptions{
		CurrentVersion: plan.Version, Mode: ModeDesktop, ListenAddress: "127.0.0.1:18080",
		ExecutablePath: target, Source: source, StopFunc: func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)

	manager.reconcileTransaction(true)
	before := manager.Status()
	if before.Phase != PhaseSucceeded || !strings.Contains(before.Message, "не удалось удалить") {
		t.Fatalf("cleanup warning status = %#v", before)
	}
	if _, err := manager.Check(context.Background()); err != nil {
		t.Fatalf("Check: %v", err)
	}
	after := manager.Status()
	if after.Phase != PhaseSucceeded || after.Message != before.Message {
		t.Fatalf("Check hid successful cleanup warning: before=%#v after=%#v", before, after)
	}
	if _, err := manager.StartInstall("v0.45"); err == nil || !strings.Contains(err.Error(), "unfinished update transaction") {
		t.Fatalf("install with unresolved cleanup plan error = %v", err)
	}
}

func TestReconcileKeepsRollbackCopiesWhenOldTargetSyncFails(t *testing.T) {
	directory := t.TempDir()
	oldContent := []byte("old executable")
	newContent := []byte("new executable")
	target := filepath.Join(directory, executableName)
	if err := os.WriteFile(target, oldContent, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := updatePaths(directory)
	for path, content := range map[string][]byte{paths.Backup: oldContent, paths.Recovery: oldContent, paths.Stage: newContent} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	token := strings.Repeat("a", 64)
	createdAt := time.Now().UTC().Add(-time.Second)
	plan := HandoffPlan{
		Format: handoffPlanFormat, FormatVersion: 2, TargetPath: target,
		StagePath: paths.Stage, BackupPath: paths.Backup, RecoveryPath: paths.Recovery,
		PlanPath: paths.Plan, ReadyPath: paths.Ready, ProceedPath: paths.Proceed, StatePath: paths.State,
		Version: "v0.44", OldVersion: "v0.43", OldSHA256: managerSHA256(oldContent), NewSHA256: managerSHA256(newContent),
		UpdateToken: token, TransactionID: transactionIDForToken(token), CreatedAt: createdAt,
	}
	mustWriteManagerJSON(t, paths.Plan, plan)
	mustWriteManagerJSON(t, paths.State, Status{
		Phase: PhaseFailed, Version: plan.Version, TransactionID: plan.TransactionID, UpdatedAt: createdAt.Add(time.Second),
	})
	manager, err := NewManager(ManagerOptions{
		CurrentVersion: plan.OldVersion, Mode: ModeDesktop, ListenAddress: "127.0.0.1:18080",
		ExecutablePath: target, Source: &managerTestSource{}, StopFunc: func() {},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	manager.syncTarget = func(string) error { return errors.New("simulated flush failure") }
	manager.reconcileTransaction(true)
	status := manager.Status()
	if status.Phase != PhaseFailed || !strings.Contains(status.Error, "резервные копии сохранены") {
		t.Fatalf("sync failure status = %#v", status)
	}
	for _, path := range []string{paths.Plan, paths.Backup, paths.Recovery} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("rollback artifact %s was removed after sync failure: %v", path, err)
		}
	}
}

type managerTestSource struct {
	mu         sync.Mutex
	releases   []Release
	listError  error
	stage      func(context.Context, Release, string, func(int64, int64)) error
	listCalls  int
	stageCalls int
}

func (s *managerTestSource) ListReleases(ctx context.Context) ([]Release, error) {
	s.mu.Lock()
	s.listCalls++
	releases := append([]Release(nil), s.releases...)
	err := s.listError
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return releases, nil
	}
}

func (s *managerTestSource) Stage(ctx context.Context, release Release, destination string, progress func(int64, int64)) error {
	s.mu.Lock()
	s.stageCalls++
	stage := s.stage
	s.mu.Unlock()
	if stage == nil {
		return errors.New("unexpected Stage call")
	}
	return stage(ctx, release, destination, progress)
}

func (s *managerTestSource) callCounts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listCalls, s.stageCalls
}

func newManagerTestFixture(t *testing.T, current string, source Source, handoff func(HandoffPlan) error, stop func()) (*Manager, string) {
	t.Helper()
	directory := t.TempDir()
	executablePath := filepath.Join(directory, "pitchProx.exe")
	if err := os.WriteFile(executablePath, []byte("current pitchProx executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if handoff == nil {
		handoff = func(HandoffPlan) error { return errors.New("handoff is not expected in this test") }
	}
	if stop == nil {
		stop = func() {}
	}
	manager, err := NewManager(ManagerOptions{
		CurrentVersion: current,
		Mode:           ModeDesktop,
		ListenAddress:  "127.0.0.1:18080",
		ExecutablePath: executablePath,
		Source:         source,
		StopFunc:       stop,
		Handoff:        handoff,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(manager.Close)
	return manager, directory
}

func managerSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func mustWriteManagerJSON(t *testing.T, path string, value any) {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
