//go:build windows

package updater

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRequestHealthUsesBoundedLoopbackResponse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		fail   bool
	}{
		{"valid", 200, `{"ok":true,"version":"v0.45","pid":123,"update_token":"token"}`, false},
		{"oversized", 200, strings.Repeat(" ", 8<<10) + `{"ok":true}`, true},
		{"redirect", 302, `{}`, true},
		{"invalid", 200, `{`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/health" {
					t.Errorf("unexpected health request: %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Location", "http://192.0.2.1/should-not-follow")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			health, err := requestHealth(strings.TrimPrefix(server.URL, "http://"))
			if (err != nil) != tc.fail || (!tc.fail && (!health.OK || health.PID != 123 || health.UpdateToken != "token")) {
				t.Fatalf("health=%+v err=%v", health, err)
			}
		})
	}
	if _, err := requestHealth("192.0.2.1:80"); err == nil {
		t.Fatal("non-loopback health address accepted")
	}
}

func TestWindowsUpdateLockBatonExcludesOtherManagers(t *testing.T) {
	directory := updaterTestTempDir(t)
	target := filepath.Join(directory, executableName)
	mustWriteWindowsTestFile(t, target, []byte("target"))

	managerLock, err := acquireUpdateLock(target)
	if err != nil {
		t.Fatalf("acquire manager lock: %v", err)
	}
	helperLock, err := observeUpdateLock(target)
	if err != nil {
		_ = managerLock.Close()
		t.Fatalf("observe manager lock: %v", err)
	}
	if competing, err := acquireUpdateLock(target); err == nil {
		_ = competing.Close()
		t.Fatal("a competing manager acquired the lock while the transfer guard was held")
	}
	released, err := managerLock.ReleaseForHandoff()
	if !released {
		_ = helperLock.Close()
		t.Fatalf("manager lock was not released: %v", err)
	}
	if err := helperLock.waitAcquire(time.Second); err != nil {
		_ = helperLock.Close()
		t.Fatalf("helper did not acquire baton: %v", err)
	}
	if competing, err := acquireUpdateLock(target); err == nil {
		_ = competing.Close()
		_ = helperLock.Close()
		t.Fatal("a competing manager acquired the helper-owned lock")
	}
	if err := helperLock.Close(); err != nil {
		t.Fatalf("close helper lock: %v", err)
	}
	finalLock, err := acquireUpdateLock(target)
	if err != nil {
		t.Fatalf("lock was not reusable after helper exit: %v", err)
	}
	if err := finalLock.Close(); err != nil {
		t.Fatalf("close final lock: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, lockFileName)); err != nil {
		t.Fatalf("fixed lock file should remain reusable instead of being path-raced: %v", err)
	}
}

func TestHelperReadyMatcherUsesFullTransactionIdentity(t *testing.T) {
	plan := HandoffPlan{UpdateToken: strings.Repeat("a", 64), TransactionID: strings.Repeat("b", 64), ParentStarted: 42}
	ready := helperReady{Phase: "observing", Token: plan.UpdateToken, TransactionID: plan.TransactionID, ParentStarted: plan.ParentStarted, HelperPID: 100}
	if !helperReadyMatches(ready, "observing", plan, 100) {
		t.Fatal("matching helper acknowledgement was rejected")
	}
	for name, mutate := range map[string]func(*helperReady){
		"phase":       func(value *helperReady) { value.Phase = "acquired" },
		"token":       func(value *helperReady) { value.Token = strings.Repeat("c", 64) },
		"transaction": func(value *helperReady) { value.TransactionID = strings.Repeat("d", 64) },
		"parent":      func(value *helperReady) { value.ParentStarted++ },
		"pid":         func(value *helperReady) { value.HelperPID++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := ready
			mutate(&changed)
			if helperReadyMatches(changed, "observing", plan, 100) {
				t.Fatal("mismatched helper acknowledgement was accepted")
			}
		})
	}
}

func TestVerifyActiveTransactionIsBoundToPlan(t *testing.T) {
	directory := updaterTestTempDir(t)
	token := strings.Repeat("a", 64)
	createdAt := time.Now().UTC().Add(-time.Second)
	plan := HandoffPlan{
		StatePath: filepath.Join(directory, stateFileName), Version: "v0.44",
		UpdateToken: token, TransactionID: mustTransactionID(t, token), CreatedAt: createdAt,
	}
	active := Status{
		Phase: PhaseRestarting, Busy: true, Version: plan.Version,
		TransactionID: plan.TransactionID, UpdatedAt: createdAt.Add(time.Second),
	}
	if err := writeJSONAtomic(plan.StatePath, active); err != nil {
		t.Fatal(err)
	}
	if err := verifyActiveTransaction(plan); err != nil {
		t.Fatalf("active transaction rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Status){
		"terminal":    func(value *Status) { value.Phase, value.Busy = PhaseFailed, false },
		"version":     func(value *Status) { value.Version = "v0.45" },
		"transaction": func(value *Status) { value.TransactionID = strings.Repeat("f", 64) },
		"stale":       func(value *Status) { value.UpdatedAt = createdAt.Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := active
			mutate(&changed)
			if err := writeJSONAtomic(plan.StatePath, changed); err != nil {
				t.Fatal(err)
			}
			if err := verifyActiveTransaction(plan); err == nil {
				t.Fatal("inactive or unrelated transaction was accepted")
			}
		})
	}
}

func TestProceedPermissionRequiresFullHelperIdentity(t *testing.T) {
	directory := updaterTestTempDir(t)
	plan := HandoffPlan{
		ProceedPath: filepath.Join(directory, proceedFileName),
		UpdateToken: strings.Repeat("a", 64), TransactionID: strings.Repeat("b", 64), ParentStarted: 42,
	}
	permission := helperReady{
		Phase: "proceed", Token: plan.UpdateToken, TransactionID: plan.TransactionID,
		ParentStarted: plan.ParentStarted, HelperPID: 100,
	}
	if err := writeJSONAtomic(plan.ProceedPath, permission); err != nil {
		t.Fatal(err)
	}
	if err := waitForProceedPermission(plan, 100, 100*time.Millisecond); err != nil {
		t.Fatalf("matching proceed permission was rejected: %v", err)
	}
	permission.TransactionID = strings.Repeat("c", 64)
	if err := writeJSONAtomic(plan.ProceedPath, permission); err != nil {
		t.Fatal(err)
	}
	if err := waitForProceedPermission(plan, 100, 50*time.Millisecond); err == nil {
		t.Fatal("permission from another transaction was accepted")
	}
}

func TestReplaceAndInventoryKeepsVerifiedRollbackSource(t *testing.T) {
	for _, test := range []struct {
		name            string
		recoveryContent []byte
	}{
		{name: "valid recovery", recoveryContent: []byte("old executable")},
		{name: "invalid recovery with valid ReplaceFile backup", recoveryContent: []byte("damaged recovery")},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := updaterTestTempDir(t)
			oldContent := []byte("old executable")
			newContent := []byte("new executable")
			plan := windowsReplacementPlan(directory, oldContent, newContent)
			mustWriteWindowsTestFile(t, plan.TargetPath, oldContent)
			mustWriteWindowsTestFile(t, plan.StagePath, newContent)
			mustWriteWindowsTestFile(t, plan.RecoveryPath, test.recoveryContent)

			state, err := replaceAndInventory(plan)
			if state != replacementNew {
				t.Fatalf("replacement state=%d err=%v, want new", state, err)
			}
			if !targetHasHash(plan.TargetPath, plan.NewSHA256) {
				t.Fatal("new target hash was not installed")
			}
			if !targetHasHash(plan.BackupPath, plan.OldSHA256) {
				t.Fatal("ReplaceFile backup does not contain the verified old executable")
			}
		})
	}
}

func TestRestoreOldExecutableFallsBackAcrossVerifiedSources(t *testing.T) {
	directory := updaterTestTempDir(t)
	oldContent := []byte("old executable")
	newContent := []byte("new executable")
	plan := windowsReplacementPlan(directory, oldContent, newContent)
	mustWriteWindowsTestFile(t, plan.TargetPath, newContent)
	if err := os.Mkdir(plan.BackupPath, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWriteWindowsTestFile(t, plan.RecoveryPath, oldContent)

	restored, err := restoreOldExecutable(plan)
	if !restored || err != nil {
		t.Fatalf("restore result restored=%v err=%v", restored, err)
	}
	if !targetHasHash(plan.TargetPath, plan.OldSHA256) {
		t.Fatal("verified recovery source was not used after backup inspection failed")
	}
}

func TestReplaceAndInventoryLeavesOldTargetWhenStageIsUnavailable(t *testing.T) {
	directory := updaterTestTempDir(t)
	oldContent := []byte("old executable")
	newContent := []byte("new executable")
	plan := windowsReplacementPlan(directory, oldContent, newContent)
	mustWriteWindowsTestFile(t, plan.TargetPath, oldContent)

	state, err := replaceAndInventory(plan)
	if state != replacementOld || err == nil {
		t.Fatalf("replacement state=%d err=%v, want old with an error", state, err)
	}
	if !targetHasHash(plan.TargetPath, plan.OldSHA256) {
		t.Fatal("old target changed after unavailable stage")
	}
}

func windowsReplacementPlan(directory string, oldContent, newContent []byte) HandoffPlan {
	return HandoffPlan{
		TargetPath:   filepath.Join(directory, executableName),
		StagePath:    filepath.Join(directory, stageFileName),
		BackupPath:   filepath.Join(directory, backupFileName),
		RecoveryPath: filepath.Join(directory, recoveryFileName),
		OldSHA256:    managerSHA256(oldContent), NewSHA256: managerSHA256(newContent),
	}
}

func mustWriteWindowsTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreOldExecutableReportsMissingSources(t *testing.T) {
	directory := updaterTestTempDir(t)
	plan := windowsReplacementPlan(directory, []byte("old"), []byte("new"))
	mustWriteWindowsTestFile(t, plan.TargetPath, []byte("unknown"))
	restored, err := restoreOldExecutable(plan)
	if restored || err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restored=%v err=%v, want a descriptive unavailable-source error", restored, err)
	}
}
