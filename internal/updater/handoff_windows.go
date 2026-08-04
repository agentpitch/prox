//go:build windows

package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	waitTimeout          = uint32(258)
	parentExitTimeout    = 2 * time.Minute
	serviceStateTimeout  = 45 * time.Second
	newProcessTimeout    = 45 * time.Second
	healthSuccessCount   = 3
	updateTokenEnv       = "PITCHPROX_UPDATE_TOKEN"
	moveFileReplaceFlags = windows.MOVEFILE_REPLACE_EXISTING | windows.MOVEFILE_WRITE_THROUGH
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procReplaceFileW   = kernel32.NewProc("ReplaceFileW")
	procIsProcessInJob = kernel32.NewProc("IsProcessInJob")
)

type helperReady struct {
	Phase         string `json:"phase"`
	Token         string `json:"token"`
	TransactionID string `json:"transaction_id"`
	HelperPID     int    `json:"helper_pid"`
	ParentStarted uint64 `json:"parent_started"`
}

type windowsUpdateLock struct {
	file       *os.File
	path       string
	owned      bool
	guardOwned bool
}

func acquireUpdateLock(target string) (platformUpdateLock, error) {
	path := filepath.Join(filepath.Dir(target), lockFileName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open update lock: %w", err)
	}
	lock := &windowsUpdateLock{file: file, path: path}
	if err := lock.acquireManagerRange(); err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errors.New("another pitchProx update transaction is active")
		}
		return nil, fmt.Errorf("acquire update lock: %w", err)
	}
	return lock, nil
}

func observeUpdateLock(target string) (*windowsUpdateLock, error) {
	path := filepath.Join(filepath.Dir(target), lockFileName)
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open manager update lock: %w", err)
	}
	lock := &windowsUpdateLock{file: file, path: path}
	if err := lock.tryAcquirePrimary(); err == nil {
		_ = lock.unlockPrimary()
		_ = file.Close()
		return nil, errors.New("update manager lock was not held before helper acknowledgement")
	} else if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		_ = file.Close()
		return nil, fmt.Errorf("verify manager update lock: %w", err)
	}
	if err := lock.lockRange(1, 1); err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errors.New("another update helper already holds the transfer guard")
		}
		return nil, fmt.Errorf("acquire update transfer guard: %w", err)
	}
	lock.guardOwned = true
	return lock, nil
}

func (l *windowsUpdateLock) lockRange(offset, length uint32) error {
	var overlapped windows.Overlapped
	overlapped.Offset = offset
	return windows.LockFileEx(windows.Handle(l.file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, length, 0, &overlapped)
}

func (l *windowsUpdateLock) unlockRange(offset, length uint32) error {
	var overlapped windows.Overlapped
	overlapped.Offset = offset
	return windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, length, 0, &overlapped)
}

func (l *windowsUpdateLock) acquireManagerRange() error {
	if err := l.lockRange(0, 1); err != nil {
		return err
	}
	l.owned = true
	if err := l.lockRange(1, 1); err != nil {
		_ = l.unlockPrimary()
		return err
	}
	l.guardOwned = true
	if err := l.unlockGuard(); err != nil {
		_ = l.unlockPrimary()
		return err
	}
	return nil
}

func (l *windowsUpdateLock) tryAcquirePrimary() error {
	err := l.lockRange(0, 1)
	if err == nil {
		l.owned = true
	}
	return err
}

func (l *windowsUpdateLock) waitAcquire(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := l.tryAcquirePrimary(); err == nil {
			if err := l.unlockGuard(); err != nil {
				_ = l.unlockPrimary()
				return err
			}
			return nil
		} else if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return err
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("update helper could not take ownership of the transaction lock")
}

func (l *windowsUpdateLock) unlockPrimary() error {
	if !l.owned {
		return nil
	}
	err := l.unlockRange(0, 1)
	if err == nil {
		l.owned = false
	}
	return err
}

func (l *windowsUpdateLock) unlockGuard() error {
	if !l.guardOwned {
		return nil
	}
	err := l.unlockRange(1, 1)
	if err == nil {
		l.guardOwned = false
	}
	return err
}

func (l *windowsUpdateLock) Close() error {
	guardErr := l.unlockGuard()
	unlockErr := l.unlockPrimary()
	closeErr := l.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	if guardErr != nil {
		return guardErr
	}
	return closeErr
}

func (l *windowsUpdateLock) ReleaseForHandoff() (bool, error) {
	unlockErr := l.unlockPrimary()
	if unlockErr != nil {
		return false, unlockErr
	}
	// Ownership is irrevocably transferred once byte 0 is unlocked. A close
	// error must not make the manager touch files that the helper can now own.
	return true, l.file.Close()
}

func currentProcessStartID() (uint64, error) {
	return processStartID(windows.CurrentProcess())
}

func processStartID(handle windows.Handle) (uint64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}

func launchHandoff(plan HandoffPlan, releaseManagerLock func() (bool, error)) error {
	helperPath := deterministicHelperPath(plan.TargetPath)
	temporary := helperPath + ".part"
	_ = os.Remove(temporary)
	if err := copyFileVerified(plan.TargetPath, temporary, plan.OldSHA256); err != nil {
		return fmt.Errorf("prepare helper: %w", err)
	}
	if err := moveFileReplace(temporary, helperPath); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("replace helper: %w", err)
	}
	if err := removeFileWithRetry(plan.ReadyPath, 5*time.Second); err != nil {
		return fmt.Errorf("remove stale helper acknowledgement: %w", err)
	}
	if err := removeFileWithRetry(plan.ProceedPath, 5*time.Second); err != nil {
		return fmt.Errorf("remove stale helper permission: %w", err)
	}

	creationFlags, err := helperCreationFlags()
	if err != nil {
		return err
	}
	command := exec.Command(helperPath, "update-helper", "--plan", plan.PlanPath)
	command.Dir = filepath.Dir(plan.TargetPath)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: creationFlags}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start update helper: %w", err)
	}
	helperPID := command.Process.Pid
	helperExit := make(chan error, 1)
	go func() {
		state, waitErr := command.Process.Wait()
		if waitErr == nil && !state.Success() {
			waitErr = fmt.Errorf("helper exited with code %d", state.ExitCode())
		}
		helperExit <- waitErr
	}()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case waitErr := <-helperExit:
			if waitErr == nil {
				waitErr = errors.New("helper exited before acknowledgement")
			}
			return waitErr
		default:
		}
		var ready helperReady
		if err := readBoundedJSON(plan.ReadyPath, &ready, 16<<10); err == nil {
			if helperReadyMatches(ready, "observing", plan, helperPID) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	var observed helperReady
	if err := readBoundedJSON(plan.ReadyPath, &observed, 16<<10); err != nil || !helperReadyMatches(observed, "observing", plan, helperPID) {
		stopErr := terminateAndConfirmHelper(command.Process, helperExit)
		if stopErr != nil {
			return fmt.Errorf("helper did not acknowledge the update plan; helper termination is uncertain: %w", stopErr)
		}
		return errors.New("helper did not acknowledge the update plan")
	}
	released, releaseErr := releaseManagerLock()
	if !released {
		stopErr := terminateAndConfirmHelper(command.Process, helperExit)
		if stopErr != nil {
			return fmt.Errorf("transfer update lock to helper: %v; helper termination is uncertain: %w", releaseErr, stopErr)
		}
		return fmt.Errorf("transfer update lock to helper: %w", releaseErr)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case waitErr := <-helperExit:
			if waitErr == nil {
				waitErr = errors.New("helper exited during lock transfer")
			}
			return waitErr
		default:
		}
		var ready helperReady
		if err := readBoundedJSON(plan.ReadyPath, &ready, 16<<10); err == nil && helperReadyMatches(ready, "acquired", plan, helperPID) {
			return authorizeHelperProceed(plan, helperPID, command.Process, helperExit)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if stopErr := terminateAndConfirmHelper(command.Process, helperExit); stopErr != nil {
		return fmt.Errorf("helper did not acquire the update transaction lock; helper termination is uncertain: %w", stopErr)
	}
	return errors.New("helper did not acquire the update transaction lock")
}

func helperReadyMatches(ready helperReady, phase string, plan HandoffPlan, helperPID int) bool {
	return ready.Phase == phase && ready.Token == plan.UpdateToken && ready.TransactionID == plan.TransactionID && ready.ParentStarted == plan.ParentStarted && ready.HelperPID == helperPID
}

func authorizeHelperProceed(plan HandoffPlan, helperPID int, process *os.Process, helperExit <-chan error) error {
	proceed := helperReady{
		Phase: "proceed", Token: plan.UpdateToken, TransactionID: plan.TransactionID,
		HelperPID: helperPID, ParentStarted: plan.ParentStarted,
	}
	if err := writeJSONAtomic(plan.ProceedPath, proceed); err != nil {
		if stopErr := terminateAndConfirmHelper(process, helperExit); stopErr != nil {
			return fmt.Errorf("%w: publishing permission returned %v and helper termination is uncertain: %v", errHandoffPossiblyCommitted, err, stopErr)
		}
		return fmt.Errorf("authorize update helper: %w", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case waitErr := <-helperExit:
			if waitErr == nil {
				waitErr = errors.New("helper exited before accepting permission")
			}
			return waitErr
		default:
		}
		var accepted helperReady
		if err := readBoundedJSON(plan.ReadyPath, &accepted, 16<<10); err == nil && helperReadyMatches(accepted, "proceeding", plan, helperPID) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	if stopErr := terminateAndConfirmHelper(process, helperExit); stopErr != nil {
		return fmt.Errorf("%w: helper did not acknowledge permission and its termination is uncertain: %v", errHandoffPossiblyCommitted, stopErr)
	}
	return errors.New("helper did not accept update permission")
}

func terminateAndConfirmHelper(process *os.Process, exited <-chan error) error {
	killErr := process.Kill()
	wait := 5 * time.Second
	if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		// Before baton transfer the helper exits by itself after its 30-second
		// lock timeout, so retain ownership long enough to observe that exit.
		wait = 35 * time.Second
	}
	select {
	case <-exited:
		return nil
	case <-time.After(wait):
		if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			return fmt.Errorf("terminate helper: %w", killErr)
		}
		return errors.New("helper process did not exit after termination")
	}
}

func removeFileWithRetry(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := os.Remove(path)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func deterministicHelperPath(target string) string {
	return filepath.Join(filepath.Dir(target), updateHelperFileName)
}

func currentProcessInJob() (bool, error) {
	var result int32
	r1, _, callErr := procIsProcessInJob.Call(uintptr(windows.CurrentProcess()), 0, uintptr(unsafe.Pointer(&result)))
	if r1 == 0 {
		if callErr == nil || callErr == windows.ERROR_SUCCESS {
			callErr = syscall.EINVAL
		}
		return false, callErr
	}
	return result != 0, nil
}

func helperCreationFlags() (uint32, error) {
	flags := uint32(windows.CREATE_NO_WINDOW)
	inJob, err := currentProcessInJob()
	if err != nil || !inJob {
		return flags, err
	}
	var information windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&information)), uint32(unsafe.Sizeof(information)), nil); err != nil {
		return 0, fmt.Errorf("query parent job limits: %w", err)
	}
	limits := information.BasicLimitInformation.LimitFlags
	if limits&windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK != 0 {
		return flags, nil
	}
	if limits&windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK != 0 {
		return flags | windows.CREATE_BREAKAWAY_FROM_JOB, nil
	}
	if limits&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0 {
		return 0, errors.New("the parent process job would terminate the update helper during restart")
	}
	return flags, nil
}

func RunHelper(planPath string) (returnErr error) {
	plan, err := loadAndValidatePlan(planPath)
	if err != nil {
		return err
	}
	transactionLock, err := observeUpdateLock(plan.TargetPath)
	if err != nil {
		return err
	}
	defer transactionLock.Close()

	parent, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, uint32(plan.ParentPID))
	if err != nil {
		return fmt.Errorf("open parent process: %w", err)
	}
	defer windows.CloseHandle(parent)
	started, err := processStartID(parent)
	if err != nil || started != plan.ParentStarted {
		return errors.New("parent process identity changed")
	}
	if plan.Mode == ModeService {
		if err := verifyServiceIdentity(plan); err != nil {
			return err
		}
	}
	if selfHash, err := hashFile(mustExecutable()); err != nil || !strings.EqualFold(selfHash, plan.OldSHA256) {
		return errors.New("helper is not an exact copy of the current executable")
	}
	if err := verifyPlanFiles(plan); err != nil {
		return err
	}
	if err := verifyActiveTransaction(plan); err != nil {
		return err
	}
	ready := helperReady{Phase: "observing", Token: plan.UpdateToken, TransactionID: plan.TransactionID, HelperPID: os.Getpid(), ParentStarted: started}
	if err := writeJSONAtomic(plan.ReadyPath, ready); err != nil {
		return fmt.Errorf("write helper acknowledgement: %w", err)
	}
	if err := transactionLock.waitAcquire(30 * time.Second); err != nil {
		failure := fmt.Errorf("take over update transaction: %w", err)
		writeHelperFailure(plan, failure)
		return failure
	}
	freshPlan, err := loadAndValidatePlan(plan.PlanPath)
	if err != nil || freshPlan != plan {
		return errors.New("update plan changed or disappeared during lock transfer")
	}
	if err := verifyPlanFiles(freshPlan); err != nil {
		return fmt.Errorf("reverify update plan after lock transfer: %w", err)
	}
	if err := verifyActiveTransaction(freshPlan); err != nil {
		return fmt.Errorf("reverify active update state after lock transfer: %w", err)
	}
	ready.Phase = "acquired"
	if err := writeJSONAtomic(plan.ReadyPath, ready); err != nil {
		return fmt.Errorf("write helper lock acknowledgement: %w", err)
	}
	if err := waitForProceedPermission(plan, os.Getpid(), 15*time.Second); err != nil {
		failure := fmt.Errorf("wait for update permission: %w", err)
		writeHelperFailure(plan, failure)
		return failure
	}
	ready.Phase = "proceeding"
	if err := writeJSONAtomic(plan.ReadyPath, ready); err != nil {
		return fmt.Errorf("write helper permission acknowledgement: %w", err)
	}

	status, err := windows.WaitForSingleObject(parent, uint32(parentExitTimeout/time.Millisecond))
	if err != nil {
		failure := fmt.Errorf("wait for application exit: %w", err)
		writeHelperFailure(plan, failure)
		return failure
	}
	if status == waitTimeout {
		if err := windows.TerminateProcess(parent, 1); err != nil {
			failure := fmt.Errorf("application did not stop and could not be terminated: %w", err)
			writeHelperFailure(plan, failure)
			return failure
		}
		status, err = windows.WaitForSingleObject(parent, 30_000)
		if err != nil || status != windows.WAIT_OBJECT_0 {
			failure := errors.New("application remained alive after termination request")
			if err != nil {
				failure = fmt.Errorf("wait after terminating application: %w", err)
			}
			writeHelperFailure(plan, failure)
			return failure
		}
	} else if status != windows.WAIT_OBJECT_0 {
		failure := fmt.Errorf("unexpected parent wait result %#x", status)
		writeHelperFailure(plan, failure)
		return failure
	}
	if plan.Mode == ModeService {
		if err := waitServiceState(plan.ServiceName, svc.Stopped, serviceStateTimeout); err != nil {
			return failAndRestartOld(plan, fmt.Errorf("confirm stopped service before replacement: %w", err))
		}
	}
	if err := verifyPlanFiles(plan); err != nil {
		return failAndRestartOld(plan, fmt.Errorf("reverify update files after shutdown: %w", err))
	}
	if err := prepareRecoveryCopy(plan); err != nil {
		return failAndRestartOld(plan, err)
	}

	replacing := Status{Phase: PhaseRestarting, Busy: true, Version: plan.Version, TransactionID: plan.TransactionID, Message: "Замена исполняемого файла…", UpdatedAt: time.Now().UTC()}
	_ = writeJSONAtomic(plan.StatePath, replacing)
	replacement, replaceErr := replaceAndInventory(plan)
	switch replacement {
	case replacementOld:
		if replaceErr == nil {
			replaceErr = errors.New("replacement did not install the new executable")
		}
		return failAndRestartOld(plan, fmt.Errorf("replace executable: %w", replaceErr))
	case replacementUnresolved:
		if replaceErr == nil {
			replaceErr = errors.New("replacement inventory is unresolved")
		}
		failure := fmt.Errorf("update file state could not be recovered: %w", replaceErr)
		writeHelperFailure(plan, failure)
		return failure
	}

	application, startErr := startApplication(plan, true)
	if startErr == nil {
		startErr = waitForHealthyApplication(plan, application, true)
	}
	if startErr == nil {
		application.close()
		succeeded := Status{Phase: PhaseSucceeded, Version: plan.Version, TransactionID: plan.TransactionID, Message: "Версия успешно установлена", UpdatedAt: time.Now().UTC()}
		if err := writeJSONAtomic(plan.StatePath, succeeded); err != nil {
			failure := fmt.Errorf("new version is healthy but its committed state could not be recorded: %w", err)
			_ = writeHelperFailure(plan, failure)
			return failure
		}
		cleanupErr := cleanupTransaction(plan, true)
		if replaceErr != nil || cleanupErr != nil {
			succeeded.Message = "Версия установлена; часть служебных файлов будет очищена при следующем запуске"
			_ = writeJSONAtomic(plan.StatePath, succeeded)
		}
		if plan.LegacyHealth {
			scheduleCurrentHelperDeletion()
		}
		return nil
	}

	if stopErr := stopApplication(plan, application); stopErr != nil {
		failure := fmt.Errorf("new version failed its startup check: %v; stopping it safely failed: %w", startErr, stopErr)
		writeHelperFailure(plan, failure)
		return failure
	}
	return failAndRestartOld(plan, fmt.Errorf("new version failed its startup check: %w", startErr))
}

func waitForProceedPermission(plan HandoffPlan, helperPID int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var proceed helperReady
		if err := readBoundedJSON(plan.ProceedPath, &proceed, 16<<10); err == nil && helperReadyMatches(proceed, "proceed", plan, helperPID) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("update permission was not received")
}

func scheduleCurrentHelperDeletion() {
	path, err := os.Executable()
	if err != nil {
		return
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	_ = windows.MoveFileEx(pointer, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}

func failAndRestartOld(plan HandoffPlan, cause error) error {
	restored, restoreErr := restoreOldExecutable(plan)
	restartErr := error(nil)
	if restored {
		restartErr = startAndVerifyOldApplication(plan)
	}
	failure := cause
	if restoreErr != nil {
		if restored {
			failure = fmt.Errorf("%v; rollback durability warning: %w", failure, restoreErr)
		} else {
			failure = fmt.Errorf("%v; rollback executable: %w", failure, restoreErr)
		}
	} else if restartErr != nil {
		failure = fmt.Errorf("%v; restart old version: %w", failure, restartErr)
	}
	if restoreErr != nil && restored && restartErr != nil {
		failure = fmt.Errorf("%v; restart old version: %w", failure, restartErr)
	}
	stateErr := writeHelperFailure(plan, failure)
	if stateErr != nil {
		failure = fmt.Errorf("%v; record rollback state: %w", failure, stateErr)
	}
	if restored && restoreErr == nil && restartErr == nil && stateErr == nil && targetHasHash(plan.TargetPath, plan.OldSHA256) {
		if cleanupErr := cleanupTransaction(plan, true); cleanupErr != nil {
			failure = fmt.Errorf("%v; %w", failure, cleanupErr)
			_ = writeHelperFailure(plan, failure)
		}
	}
	return failure
}

func loadAndValidatePlan(planPath string) (HandoffPlan, error) {
	var plan HandoffPlan
	absolutePlan, err := filepath.Abs(planPath)
	if err != nil {
		return plan, err
	}
	if err := readBoundedJSON(absolutePlan, &plan, 64<<10); err != nil {
		return plan, fmt.Errorf("read update plan: %w", err)
	}
	if plan.Format != handoffPlanFormat || plan.FormatVersion != 2 {
		return plan, errors.New("unsupported update plan")
	}
	if plan.Mode != ModeDesktop && plan.Mode != ModeService {
		return plan, errors.New("invalid update mode")
	}
	if plan.Mode == ModeService && plan.ServiceName == "" {
		return plan, errors.New("service update has no service name")
	}
	if plan.ParentPID <= 0 || plan.ParentStarted == 0 || time.Since(plan.CreatedAt) < 0 || time.Since(plan.CreatedAt) > 10*time.Minute {
		return plan, errors.New("stale or invalid update plan")
	}
	if _, ok := parseVersion(plan.Version); !ok {
		return plan, errors.New("invalid target version")
	}
	if strings.TrimSpace(plan.OldVersion) == "" || len(plan.OldVersion) > 64 || strings.ContainsRune(plan.OldVersion, 0) {
		return plan, errors.New("invalid current version")
	}
	if len(plan.UpdateToken) != 64 || len(plan.TransactionID) != 64 || len(plan.OldSHA256) != 64 || len(plan.NewSHA256) != 64 {
		return plan, errors.New("invalid update plan digest")
	}
	for _, value := range []string{plan.UpdateToken, plan.TransactionID, plan.OldSHA256, plan.NewSHA256} {
		if _, err := hex.DecodeString(value); err != nil {
			return plan, errors.New("invalid update plan digest")
		}
	}
	if plan.TransactionID != transactionIDForToken(plan.UpdateToken) {
		return plan, errors.New("update transaction identity does not match its token")
	}
	target, err := filepath.Abs(plan.TargetPath)
	if err != nil {
		return plan, err
	}
	directory := filepath.Dir(target)
	expected := updatePaths(directory)
	for name, pair := range map[string][2]string{
		"stage": {plan.StagePath, expected.Stage}, "backup": {plan.BackupPath, expected.Backup},
		"recovery": {plan.RecoveryPath, expected.Recovery},
		"plan":     {plan.PlanPath, expected.Plan}, "ready": {plan.ReadyPath, expected.Ready},
		"proceed": {plan.ProceedPath, expected.Proceed}, "state": {plan.StatePath, expected.State},
	} {
		actual, err := filepath.Abs(pair[0])
		if err != nil || !strings.EqualFold(actual, pair[1]) {
			return plan, fmt.Errorf("invalid %s path in update plan", name)
		}
	}
	if !strings.EqualFold(absolutePlan, expected.Plan) {
		return plan, errors.New("update plan path does not match its contents")
	}
	if err := validateListenAddress(plan.ListenAddress); err != nil {
		return plan, err
	}
	plan.TargetPath = target
	self, err := os.Executable()
	if err != nil {
		return plan, err
	}
	self, err = filepath.Abs(self)
	if err != nil || !strings.EqualFold(self, deterministicHelperPath(target)) {
		return plan, errors.New("update helper is not running from the installation directory")
	}
	return plan, nil
}

func verifyServiceIdentity(plan HandoffPlan) error {
	service, manager, err := openService(plan.ServiceName)
	if err != nil {
		return fmt.Errorf("open update service: %w", err)
	}
	defer manager.Disconnect()
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Running || int(status.ProcessId) != plan.ParentPID {
		return errors.New("service process does not match the update parent")
	}
	configuration, err := service.Config()
	if err != nil {
		return err
	}
	arguments, err := windows.DecomposeCommandLine(configuration.BinaryPathName)
	if err != nil || len(arguments) < 2 {
		return errors.New("service binary command line is invalid")
	}
	serviceExecutable, err := filepath.Abs(arguments[0])
	if err != nil || !strings.EqualFold(serviceExecutable, plan.TargetPath) || arguments[1] != "service" {
		return errors.New("service binary does not match the update target")
	}
	return nil
}

func validateListenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("invalid WebUI listen address")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("update health check must use a loopback address")
	}
	return nil
}

func verifyPlanFiles(plan HandoffPlan) error {
	if hash, err := hashFile(plan.TargetPath); err != nil || !strings.EqualFold(hash, plan.OldSHA256) {
		return errors.New("current executable changed after the update was prepared")
	}
	if hash, err := hashFile(plan.StagePath); err != nil || !strings.EqualFold(hash, plan.NewSHA256) {
		return errors.New("staged executable changed after verification")
	}
	if _, err := os.Stat(plan.BackupPath); err == nil {
		return errors.New("update backup already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(plan.RecoveryPath); err == nil {
		return errors.New("update recovery copy already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func verifyActiveTransaction(plan HandoffPlan) error {
	var status Status
	if err := readBoundedJSON(plan.StatePath, &status, 64<<10); err != nil {
		return fmt.Errorf("read active update state: %w", err)
	}
	if status.Phase != PhaseRestarting || !status.Busy || status.Version != plan.Version || status.TransactionID != plan.TransactionID || status.UpdatedAt.Before(plan.CreatedAt) {
		return errors.New("update transaction is no longer active")
	}
	return nil
}

type replacementState int

const (
	replacementUnresolved replacementState = iota
	replacementNew
	replacementOld
)

type fileInventory struct {
	exists bool
	hash   string
	err    error
}

func inspectFile(path string) fileInventory {
	hash, err := hashFile(path)
	if err == nil {
		return fileInventory{exists: true, hash: hash}
	}
	if errors.Is(err, os.ErrNotExist) {
		return fileInventory{}
	}
	return fileInventory{err: err}
}

func prepareRecoveryCopy(plan HandoffPlan) error {
	if err := copyFileVerified(mustExecutable(), plan.RecoveryPath, plan.OldSHA256); err != nil {
		return fmt.Errorf("create verified recovery copy: %w", err)
	}
	return nil
}

func replaceAndInventory(plan HandoffPlan) (replacementState, error) {
	if err := syncFile(plan.StagePath); err != nil {
		return replacementOld, err
	}
	replaceErr := replaceFile(plan.TargetPath, plan.StagePath, plan.BackupPath)
	target := inspectFile(plan.TargetPath)
	backup := inspectFile(plan.BackupPath)
	recovery := inspectFile(plan.RecoveryPath)
	targetOld := target.err == nil && target.exists && strings.EqualFold(target.hash, plan.OldSHA256)
	backupOld := backup.err == nil && backup.exists && strings.EqualFold(backup.hash, plan.OldSHA256)
	recoveryOld := recovery.err == nil && recovery.exists && strings.EqualFold(recovery.hash, plan.OldSHA256)
	if targetOld {
		if syncErr := syncFile(plan.TargetPath); syncErr != nil {
			return replacementOld, fmt.Errorf("old executable remains in place but could not be synchronized: %w", syncErr)
		}
		return replacementOld, replaceErr
	}
	if target.err == nil && target.exists && strings.EqualFold(target.hash, plan.NewSHA256) {
		if !backupOld && !recoveryOld {
			return replacementUnresolved, errors.New("new executable is in place but no verified old executable is available for rollback")
		}
		if err := syncFile(plan.TargetPath); err != nil {
			restored, restoreErr := restoreOldExecutable(plan)
			if !restored {
				return replacementUnresolved, fmt.Errorf("sync new executable: %v; restore old executable: %w", err, restoreErr)
			}
			if restoreErr != nil {
				return replacementOld, fmt.Errorf("new executable could not be synchronized: %v; rollback durability warning: %w", err, restoreErr)
			}
			return replacementOld, fmt.Errorf("new executable could not be synchronized: %w", err)
		}
		var warnings []string
		if replaceErr != nil {
			warnings = append(warnings, replaceErr.Error())
		}
		if backup.err != nil && recoveryOld {
			warnings = append(warnings, "backup inspection: "+backup.err.Error())
		}
		if recovery.err != nil && backupOld {
			warnings = append(warnings, "recovery inspection: "+recovery.err.Error())
		}
		if len(warnings) > 0 {
			return replacementNew, errors.New(strings.Join(warnings, "; "))
		}
		return replacementNew, nil
	}
	restored, restoreErr := restoreOldExecutable(plan)
	if !restored {
		if replaceErr != nil {
			return replacementUnresolved, fmt.Errorf("%v; restore inventory: %w", replaceErr, restoreErr)
		}
		return replacementUnresolved, restoreErr
	}
	if restoreErr != nil {
		return replacementOld, fmt.Errorf("old executable restored with a durability warning: %w", restoreErr)
	}
	if replaceErr == nil {
		replaceErr = errors.New("ReplaceFileW returned success but postcondition failed")
	}
	return replacementOld, replaceErr
}

func replaceFile(target, replacement, backup string) error {
	targetPointer, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	replacementPointer, err := windows.UTF16PtrFromString(replacement)
	if err != nil {
		return err
	}
	backupPointer, err := windows.UTF16PtrFromString(backup)
	if err != nil {
		return err
	}
	r1, _, callErr := procReplaceFileW.Call(uintptr(unsafe.Pointer(targetPointer)), uintptr(unsafe.Pointer(replacementPointer)), uintptr(unsafe.Pointer(backupPointer)), 0, 0, 0)
	if r1 == 0 {
		if callErr == nil || callErr == windows.ERROR_SUCCESS {
			callErr = syscall.EINVAL
		}
		return callErr
	}
	return nil
}

func restoreOldExecutable(plan HandoffPlan) (bool, error) {
	target := inspectFile(plan.TargetPath)
	if target.err == nil && target.exists && strings.EqualFold(target.hash, plan.OldSHA256) {
		if err := syncFile(plan.TargetPath); err != nil {
			return true, err
		}
		return true, nil
	}
	backup := inspectFile(plan.BackupPath)
	recovery := inspectFile(plan.RecoveryPath)
	var sources []string
	if backup.err == nil && backup.exists && strings.EqualFold(backup.hash, plan.OldSHA256) {
		sources = append(sources, plan.BackupPath)
	}
	if recovery.err == nil && recovery.exists && strings.EqualFold(recovery.hash, plan.OldSHA256) {
		sources = append(sources, plan.RecoveryPath)
	}
	if len(sources) == 0 {
		var details []string
		if target.err != nil {
			details = append(details, "target: "+target.err.Error())
		}
		if backup.err != nil {
			details = append(details, "backup: "+backup.err.Error())
		}
		if recovery.err != nil {
			details = append(details, "recovery: "+recovery.err.Error())
		}
		if len(details) > 0 {
			return false, errors.New("no verified old executable is available for rollback; " + strings.Join(details, "; "))
		}
		return false, errors.New("no verified old executable is available for rollback")
	}
	var restoreErrors []string
	for _, source := range sources {
		if err := moveFileReplace(source, plan.TargetPath); err != nil {
			restoreErrors = append(restoreErrors, filepath.Base(source)+": "+err.Error())
		} else if targetHasHash(plan.TargetPath, plan.OldSHA256) {
			if err := syncFile(plan.TargetPath); err != nil {
				return true, err
			}
			return true, nil
		} else {
			restoreErrors = append(restoreErrors, filepath.Base(source)+": restored executable failed SHA-256 verification")
		}
		// MoveFileEx can report a late error after changing directory entries.
		if targetHasHash(plan.TargetPath, plan.OldSHA256) {
			if err := syncFile(plan.TargetPath); err != nil {
				return true, err
			}
			return true, nil
		}
	}
	return false, errors.New("restore verified old executable: " + strings.Join(restoreErrors, "; "))
}

type launchedApplication struct {
	mode    string
	pid     uint32
	process *os.Process
	exit    <-chan error
	exited  bool
	exitErr error
	handle  windows.Handle
	service string
}

func startApplication(plan HandoffPlan, installing bool) (*launchedApplication, error) {
	if plan.Mode == ModeService {
		service, manager, err := openService(plan.ServiceName)
		if err != nil {
			return nil, err
		}
		defer manager.Disconnect()
		defer service.Close()
		application := &launchedApplication{mode: ModeService, service: plan.ServiceName}
		status, err := waitServiceStartable(service, serviceStateTimeout)
		if err != nil {
			if trackErr := application.trackServiceProcess(status); trackErr != nil {
				return application, fmt.Errorf("%v; track pending service process: %w", err, trackErr)
			}
			return application, err
		}
		if installing && status.State == svc.Running {
			// SCM recovery could have started a process before the helper got here.
			// Stop it and perform our own Start so even legacy health checks prove
			// the selected executable was launched by this transaction.
			application.pid = status.ProcessId
			if handle, openErr := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, status.ProcessId); openErr == nil {
				application.handle = handle
			}
			if err := stopApplication(plan, application); err != nil {
				return application, fmt.Errorf("stop unexpectedly running service before update start: %w", err)
			}
			application = &launchedApplication{mode: ModeService, service: plan.ServiceName}
			status = svc.Status{State: svc.Stopped}
		}
		if status.State == svc.Stopped {
			if err := service.Start(); err != nil {
				return application, err
			}
			status, err = waitServiceRunning(service, serviceStateTimeout)
			if err != nil {
				if trackErr := application.trackServiceProcess(status); trackErr != nil {
					return application, fmt.Errorf("%v; track service process after start: %w", err, trackErr)
				}
				return application, err
			}
		}
		application.pid = status.ProcessId
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, status.ProcessId)
		if err != nil {
			return application, err
		}
		application.handle = handle
		confirmed, err := service.Query()
		if err != nil || confirmed.State != svc.Running || confirmed.ProcessId != status.ProcessId {
			return application, errors.New("service process identity changed during startup")
		}
		return application, nil
	}
	command := exec.Command(plan.TargetPath, "run")
	command.Dir = filepath.Dir(plan.TargetPath)
	if installing {
		command.Env = withUpdateToken(os.Environ(), plan.UpdateToken)
	} else {
		command.Env = withoutUpdateToken(os.Environ())
	}
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if err := command.Start(); err != nil {
		return nil, err
	}
	exit := make(chan error, 1)
	process := command.Process
	go func() {
		state, waitErr := process.Wait()
		if waitErr == nil && !state.Success() {
			waitErr = fmt.Errorf("process exited with code %d", state.ExitCode())
		}
		exit <- waitErr
	}()
	return &launchedApplication{mode: ModeDesktop, pid: uint32(process.Pid), process: process, exit: exit}, nil
}

func (application *launchedApplication) alive() (bool, error) {
	if application.mode == ModeDesktop {
		if application.exited {
			return false, application.exitErr
		}
		select {
		case application.exitErr = <-application.exit:
			application.exited = true
			return false, application.exitErr
		default:
			return true, nil
		}
	}
	return processIsAlive(application.handle)
}

func (application *launchedApplication) close() {
	if application.handle != 0 {
		_ = windows.CloseHandle(application.handle)
		application.handle = 0
	}
}

func (application *launchedApplication) trackServiceProcess(status svc.Status) error {
	if status.ProcessId == 0 {
		return nil
	}
	application.pid = status.ProcessId
	if application.handle != 0 {
		return nil
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, status.ProcessId)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		application.pid = 0
		return nil
	}
	if err != nil {
		return err
	}
	application.handle = handle
	return nil
}

func waitForHealthyApplication(plan HandoffPlan, application *launchedApplication, installing bool) error {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(newProcessTimeout)
	consecutive := 0
	for time.Now().Before(deadline) {
		alive, err := application.alive()
		if err != nil || !alive {
			return errors.New("application exited before becoming healthy")
		}
		if plan.Mode == ModeService {
			status, err := queryService(plan.ServiceName)
			if err != nil || status.State != svc.Running || status.ProcessId != application.pid {
				consecutive = 0
				time.Sleep(300 * time.Millisecond)
				continue
			}
		}
		health, err := requestHealth(client, plan.ListenAddress)
		valid := err == nil && health.OK
		if valid && installing && !plan.LegacyHealth {
			valid = health.Version == plan.Version && health.PID == application.pid && health.UpdateToken == plan.UpdateToken
		} else if valid && !installing {
			valid = health.Version == plan.OldVersion && health.PID == application.pid
		}
		if valid {
			consecutive++
			if consecutive >= healthSuccessCount {
				return nil
			}
		} else {
			consecutive = 0
		}
		time.Sleep(400 * time.Millisecond)
	}
	return errors.New("application did not pass the health check")
}

type healthResponse struct {
	OK          bool   `json:"ok"`
	Version     string `json:"version"`
	PID         uint32 `json:"pid"`
	UpdateToken string `json:"update_token"`
}

func requestHealth(client *http.Client, address string) (healthResponse, error) {
	var health healthResponse
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+address+"/api/health", nil)
	if err != nil {
		return health, err
	}
	response, err := client.Do(request)
	if err != nil {
		return health, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return health, fmt.Errorf("health returned HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 8<<10))
	if err != nil {
		return health, err
	}
	if err := json.Unmarshal(content, &health); err != nil {
		return health, err
	}
	return health, nil
}

func stopApplication(plan HandoffPlan, application *launchedApplication) error {
	if application == nil {
		return nil
	}
	defer application.close()
	if application.mode == ModeService {
		if application.pid != 0 && application.handle == 0 {
			if err := application.trackServiceProcess(svc.Status{ProcessId: application.pid}); err != nil {
				return fmt.Errorf("track service process before stopping it: %w", err)
			}
		}
		service, manager, err := openService(plan.ServiceName)
		if err != nil {
			return err
		}
		_, controlErr := service.Control(svc.Stop)
		_ = service.Close()
		_ = manager.Disconnect()
		if controlErr != nil && !errors.Is(controlErr, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return controlErr
		}
		if err := waitServiceState(plan.ServiceName, svc.Stopped, serviceStateTimeout); err != nil {
			return err
		}
		if application.handle != 0 {
			status, waitErr := windows.WaitForSingleObject(application.handle, 10_000)
			if waitErr != nil || status != windows.WAIT_OBJECT_0 {
				return errors.New("service process remained alive after SCM reported stopped")
			}
		}
		return nil
	}
	if application.exited {
		return nil
	}
	if err := application.process.Kill(); err != nil {
		alive, aliveErr := application.alive()
		if !alive {
			return nil
		}
		if aliveErr != nil {
			return aliveErr
		}
		if alive {
			return err
		}
	}
	select {
	case application.exitErr = <-application.exit:
		application.exited = true
		return nil
	case <-time.After(10 * time.Second):
		return errors.New("desktop process remained alive after termination")
	}
}

func startAndVerifyOldApplication(plan HandoffPlan) error {
	application, err := startApplication(plan, false)
	if err != nil {
		if application != nil {
			if stopErr := stopApplication(plan, application); stopErr != nil {
				return fmt.Errorf("start old application: %v; stop uncertain service start: %w", err, stopErr)
			}
		}
		return err
	}
	if err := waitForHealthyApplication(plan, application, false); err != nil {
		_ = stopApplication(plan, application)
		return err
	}
	application.close()
	return nil
}

func openService(name string) (*mgr.Service, *mgr.Mgr, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	service, err := manager.OpenService(name)
	if err != nil {
		_ = manager.Disconnect()
		return nil, nil, err
	}
	return service, manager, nil
}

func waitServiceState(name string, wanted svc.State, timeout time.Duration) error {
	service, manager, err := openService(name)
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == wanted {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("service did not reach state %d", wanted)
}

func waitServiceRunning(service *mgr.Service, timeout time.Duration) (svc.Status, error) {
	deadline := time.Now().Add(timeout)
	var last svc.Status
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return last, err
		}
		last = status
		if status.State == svc.Running && status.ProcessId != 0 {
			return status, nil
		}
		if status.State == svc.Stopped && status.Win32ExitCode != 0 {
			return svc.Status{}, fmt.Errorf("service stopped with exit code %d", status.Win32ExitCode)
		}
		time.Sleep(250 * time.Millisecond)
	}
	return last, errors.New("service did not become running")
}

func waitServiceStartable(service *mgr.Service, timeout time.Duration) (svc.Status, error) {
	deadline := time.Now().Add(timeout)
	var last svc.Status
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return last, err
		}
		last = status
		if status.State == svc.Stopped || (status.State == svc.Running && status.ProcessId != 0) {
			return status, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return last, errors.New("service did not reach a startable state")
}

func queryService(name string) (svc.Status, error) {
	service, manager, err := openService(name)
	if err != nil {
		return svc.Status{}, err
	}
	defer manager.Disconnect()
	defer service.Close()
	return service.Query()
}

func processIsAlive(handle windows.Handle) (bool, error) {
	status, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return false, err
	}
	return status == waitTimeout, nil
}

func targetHasHash(path, expected string) bool {
	file := inspectFile(path)
	return file.err == nil && file.exists && strings.EqualFold(file.hash, expected)
}

func syncFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func syncUpdateTarget(path string) error { return syncFile(path) }

func copyFileVerified(source, destination, expectedHash string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = output.Close()
		if !keep {
			_ = os.Remove(destination)
		}
	}()
	hash := sha256.New()
	if _, err := io.CopyBuffer(io.MultiWriter(output, hash), input, make([]byte, 64<<10)); err != nil {
		return err
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expectedHash) {
		return errors.New("copied file SHA-256 verification failed")
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}

func moveFileReplace(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, moveFileReplaceFlags)
}

func replacePath(source, destination string) error {
	return moveFileReplace(source, destination)
}

func cleanupTransaction(plan HandoffPlan, committed bool) error {
	if !committed {
		return nil
	}
	var failures []string
	for _, path := range []string{plan.StagePath, plan.StagePath + ".part", plan.RecoveryPath, plan.ReadyPath, plan.ProceedPath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, filepath.Base(path)+": "+err.Error())
		}
	}
	if err := os.Remove(plan.BackupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		failures = append(failures, filepath.Base(plan.BackupPath)+": "+err.Error())
	}
	if len(failures) == 0 {
		if err := os.Remove(plan.PlanPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, filepath.Base(plan.PlanPath)+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return errors.New("cleanup update transaction: " + strings.Join(failures, "; "))
	}
	return nil
}

func writeHelperFailure(plan HandoffPlan, err error) error {
	status := Status{Phase: PhaseFailed, Version: plan.Version, TransactionID: plan.TransactionID, Error: err.Error(), UpdatedAt: time.Now().UTC()}
	return writeJSONAtomic(plan.StatePath, status)
}

func mustExecutable() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return path
}

func withUpdateToken(environment []string, token string) []string {
	result := withoutUpdateToken(environment)
	return append(result, updateTokenEnv+"="+token)
}

func withoutUpdateToken(environment []string) []string {
	prefix := strings.ToUpper(updateTokenEnv) + "="
	result := make([]string, 0, len(environment))
	for _, entry := range environment {
		if !strings.HasPrefix(strings.ToUpper(entry), prefix) {
			result = append(result, entry)
		}
	}
	return result
}

func HelperPlanPathFromArgs(args []string) (string, error) {
	if len(args) != 2 || args[0] != "--plan" || strings.TrimSpace(args[1]) == "" {
		return "", errors.New("usage: update-helper --plan <path>")
	}
	return args[1], nil
}
