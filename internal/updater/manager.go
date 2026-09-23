package updater

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/agentpitch/prox/internal/platformcrypto"
)

const (
	ModeDesktop        = "desktop"
	ModeService        = "service"
	maxVisibleReleases = 5

	stageFileName    = ".pitchProx-update-stage.exe"
	backupFileName   = ".pitchProx-update-backup.exe"
	recoveryFileName = ".pitchProx-update-recovery.exe"
	planFileName     = ".pitchProx-update-plan.json"
	readyFileName    = ".pitchProx-update-ready"
	proceedFileName  = ".pitchProx-update-proceed"
	stateFileName    = ".pitchProx-update-state.json"
	lockFileName     = ".pitchProx-update.lock"
)

var errHandoffPossiblyCommitted = errors.New("update helper may have accepted permission")

type Service interface {
	Check(context.Context) (CheckResult, error)
	StartInstall(string) (Status, error)
	Status() Status
	HealthToken() string
	Close()
}

type ManagerOptions struct {
	CurrentVersion        string
	Mode                  string
	ServiceName           string
	ListenAddress         string
	ListenAddressProvider func() string
	ExecutablePath        string
	Source                Source
	StopFunc              func()
	Handoff               func(HandoffPlan) error
}

type Manager struct {
	currentVersion string
	mode           string
	serviceName    string
	listenAddress  string
	listenProvider func() string
	syncTarget     func(string) error
	executablePath string
	directory      string
	source         Source
	stopFunc       func()
	handoff        func(HandoffPlan, func() (bool, error)) error
	customHandoff  bool

	mu              sync.Mutex
	status          Status
	cache           []Release
	cacheAt         time.Time
	active          bool
	closed          bool
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	maintenanceWG   sync.WaitGroup
	stateReload     bool
	healthToken     string
	updateLock      platformUpdateLock
	lockHandoff     bool
	lockRetained    bool
	maintenanceStop chan struct{}
	maintenanceOnce sync.Once
	reconcileMemo   string
}

func NewManager(options ManagerOptions) (*Manager, error) {
	executablePath := strings.TrimSpace(options.ExecutablePath)
	if executablePath == "" {
		var err error
		executablePath, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("locate executable: %w", err)
		}
	}
	absolute, err := filepath.Abs(executablePath)
	if err != nil {
		return nil, fmt.Errorf("resolve executable path: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("update target is not a regular file: %s", absolute)
	}
	mode := options.Mode
	if mode != ModeDesktop && mode != ModeService {
		return nil, fmt.Errorf("unsupported update mode %q", mode)
	}
	source := options.Source
	if source == nil {
		source, err = NewGitHubClient(ClientOptions{})
		if err != nil {
			return nil, err
		}
	}
	var handoff func(HandoffPlan, func() (bool, error)) error
	if options.Handoff == nil {
		handoff = launchHandoff
	} else {
		handoff = func(plan HandoffPlan, releaseLock func() (bool, error)) error {
			if err := options.Handoff(plan); err != nil {
				return err
			}
			released, err := releaseLock()
			if !released {
				return err
			}
			return nil
		}
	}
	if options.StopFunc == nil {
		return nil, errors.New("application stop callback is required")
	}
	m := &Manager{
		currentVersion:  strings.TrimSpace(options.CurrentVersion),
		mode:            mode,
		serviceName:     options.ServiceName,
		listenAddress:   options.ListenAddress,
		listenProvider:  options.ListenAddressProvider,
		syncTarget:      syncUpdateTarget,
		executablePath:  absolute,
		directory:       filepath.Dir(absolute),
		source:          source,
		stopFunc:        options.StopFunc,
		handoff:         handoff,
		customHandoff:   options.Handoff != nil,
		status:          Status{Phase: PhaseIdle, UpdatedAt: time.Now().UTC()},
		maintenanceStop: make(chan struct{}),
	}
	if m.listenProvider == nil {
		m.listenProvider = func() string { return m.listenAddress }
	}
	m.loadPersistedState()
	m.loadHealthToken()
	m.startDelayedReconciliation()
	return m, nil
}

func (m *Manager) startDelayedReconciliation() {
	m.maintenanceWG.Add(1)
	go func() {
		defer m.maintenanceWG.Done()
		for _, delay := range []time.Duration{3 * time.Second, 7 * time.Second, 15 * time.Second, 30 * time.Second, 65 * time.Second} {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-m.maintenanceStop:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			}
			m.reconcileTransaction(true)
			if _, err := os.Stat(filepath.Join(m.directory, planFileName)); errors.Is(err, os.ErrNotExist) {
				if m.cleanupDormantHelper() {
					return
				}
			}
		}
	}()
}

func (m *Manager) cleanupDormantHelper() bool {
	lock, err := acquireUpdateLock(m.executablePath)
	if err != nil {
		return false
	}
	defer lock.Close()
	if _, err := os.Stat(filepath.Join(m.directory, planFileName)); !errors.Is(err, os.ErrNotExist) {
		return false
	}
	err = os.Remove(filepath.Join(m.directory, updateHelperFileName))
	return err == nil || errors.Is(err, os.ErrNotExist)
}

func (m *Manager) Check(ctx context.Context) (CheckResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.reconcileTransaction(true)
	_, planErr := os.Stat(filepath.Join(m.directory, planFileName))
	planPresent := planErr == nil || !errors.Is(planErr, os.ErrNotExist)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return CheckResult{}, errors.New("updater is closed")
	}
	if m.active || m.status.Busy || m.lockRetained {
		m.mu.Unlock()
		return CheckResult{}, errors.New("an update operation is already running")
	}
	unresolved := planPresent && (m.status.Phase == PhaseFailed || m.status.Phase == PhaseSucceeded)
	unresolvedStatus := m.status
	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.active = true
	m.wg.Add(1)
	if !unresolved {
		m.status = Status{Phase: PhaseChecking, Busy: true, Message: "Проверка релизов GitHub…", UpdatedAt: time.Now().UTC()}
	}
	m.mu.Unlock()
	defer m.wg.Done()
	defer cancel()

	releases, err := m.source.ListReleases(ctx)
	now := time.Now().UTC()
	visibleReleases := limitVisibleReleases(releases)
	m.mu.Lock()
	m.active = false
	m.cancel = nil
	if err != nil {
		if unresolved && transactionPlanExists(m.directory) {
			m.status = unresolvedStatus
		} else {
			m.status = Status{Phase: PhaseFailed, Error: err.Error(), UpdatedAt: now}
		}
		m.mu.Unlock()
		return CheckResult{}, err
	}
	m.cache = append(m.cache[:0], visibleReleases...)
	m.cacheAt = now
	if unresolved && transactionPlanExists(m.directory) {
		m.status = unresolvedStatus
	} else {
		m.status = Status{Phase: PhaseIdle, Message: "Проверка завершена", UpdatedAt: now}
	}
	m.mu.Unlock()
	return makeCheckResult(m.currentVersion, visibleReleases, releases, now), nil
}

func makeCheckResult(current string, visibleReleases, comparisonReleases []Release, checkedAt time.Time) CheckResult {
	result := CheckResult{
		CurrentVersion: current,
		CheckedAt:      checkedAt,
		Releases:       visibleReleases,
	}
	var latest string
	for _, release := range comparisonReleases {
		if release.Prerelease {
			continue
		}
		if latest == "" {
			if _, ok := parseVersion(release.Version); ok {
				latest = release.Version
			}
			continue
		}
		if comparison, known := compareVersions(release.Version, latest); known && comparison > 0 {
			latest = release.Version
		}
	}
	result.LatestVersion = latest
	if latest != "" {
		comparison, known := compareVersions(current, latest)
		result.ComparisonKnown = known
		result.UpdateAvailable = known && comparison < 0
	}
	return result
}

func limitVisibleReleases(releases []Release) []Release {
	limit := min(len(releases), maxVisibleReleases)
	visible := append([]Release(nil), releases[:limit]...)
	if visible == nil {
		visible = []Release{}
	}
	return visible
}

func (m *Manager) StartInstall(version string) (Status, error) {
	version = strings.TrimSpace(version)
	if _, ok := parseVersion(version); !ok {
		return Status{}, errors.New("invalid release version")
	}
	m.reconcileTransaction(true)
	planExists := transactionPlanExists(m.directory)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return Status{}, errors.New("updater is closed")
	}
	if m.active || m.status.Busy || m.lockRetained {
		status := m.status
		m.mu.Unlock()
		return status, errors.New("an update operation is already running")
	}
	if planExists {
		status := m.status
		m.mu.Unlock()
		return status, errors.New("an unfinished update transaction must be resolved before another version can be installed")
	}
	if comparison, known := compareVersions(m.currentVersion, version); known && comparison == 0 {
		status := Status{Phase: PhaseSucceeded, Version: version, Message: "Выбранная версия уже установлена", UpdatedAt: time.Now().UTC()}
		m.status = status
		m.mu.Unlock()
		return status, nil
	}
	updateLock, err := acquireUpdateLock(m.executablePath)
	if err != nil {
		m.mu.Unlock()
		return Status{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	m.cancel = cancel
	m.updateLock = updateLock
	m.lockHandoff = false
	m.lockRetained = false
	m.active = true
	m.stateReload = false
	m.status = Status{Phase: PhaseChecking, Busy: true, Version: version, Message: "Подготовка обновления…", UpdatedAt: time.Now().UTC()}
	status := m.status
	m.wg.Add(1)
	go m.install(ctx, cancel, version)
	m.mu.Unlock()
	return status, nil
}

func transactionPlanExists(directory string) bool {
	_, err := os.Stat(filepath.Join(directory, planFileName))
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

func (m *Manager) install(ctx context.Context, cancel context.CancelFunc, version string) {
	defer m.wg.Done()
	defer cancel()
	defer func() {
		m.mu.Lock()
		m.active = false
		m.cancel = nil
		if m.updateLock != nil && !m.lockHandoff && !m.lockRetained {
			_ = m.updateLock.Close()
			m.updateLock = nil
		}
		m.mu.Unlock()
	}()

	release, err := m.resolveRelease(ctx, version)
	if err != nil {
		m.fail(version, err)
		return
	}
	if !release.Installable {
		m.fail(version, fmt.Errorf("release cannot be installed: %s", release.Reason))
		return
	}
	paths := updatePaths(m.directory)
	if err := prepareTransactionPaths(paths); err != nil {
		m.fail(version, err)
		return
	}
	m.setStatus(Status{Phase: PhaseDownloading, Busy: true, Version: version, Message: "Загрузка и проверка файлов…", TotalBytes: release.Size, UpdatedAt: time.Now().UTC()})
	if err := m.source.Stage(ctx, release, paths.Stage, func(downloaded, total int64) {
		m.mu.Lock()
		if m.status.Phase == PhaseDownloading {
			m.status.DownloadedBytes = downloaded
			m.status.TotalBytes = total
			m.status.UpdatedAt = time.Now().UTC()
		}
		m.mu.Unlock()
	}); err != nil {
		_ = os.Remove(paths.Stage)
		_ = os.Remove(paths.Stage + ".part")
		m.fail(version, err)
		return
	}
	m.setStatus(Status{Phase: PhaseVerifying, Busy: true, Version: version, Message: "Подготовка безопасной замены…", DownloadedBytes: release.Size, TotalBytes: release.Size, UpdatedAt: time.Now().UTC()})
	oldHash, err := hashFile(m.executablePath)
	if err != nil {
		_ = os.Remove(paths.Stage)
		m.fail(version, fmt.Errorf("hash current executable: %w", err))
		return
	}
	newHash, err := hashFile(paths.Stage)
	if err != nil {
		_ = os.Remove(paths.Stage)
		m.fail(version, fmt.Errorf("hash staged executable: %w", err))
		return
	}
	parentStarted, err := currentProcessStartID()
	if err != nil {
		_ = os.Remove(paths.Stage)
		m.fail(version, fmt.Errorf("identify current process: %w", err))
		return
	}
	token, err := randomToken()
	if err != nil {
		_ = os.Remove(paths.Stage)
		m.fail(version, err)
		return
	}
	transactionID, err := transactionIDForToken(token)
	if err != nil {
		_ = os.Remove(paths.Stage)
		m.fail(version, fmt.Errorf("derive update transaction: %w", err))
		return
	}
	listenAddress := strings.TrimSpace(m.listenProvider())
	if listenAddress == "" {
		_ = os.Remove(paths.Stage)
		m.fail(version, errors.New("WebUI listen address is empty"))
		return
	}
	plan := HandoffPlan{
		Format:        handoffPlanFormat,
		FormatVersion: 2,
		Mode:          m.mode,
		ServiceName:   m.serviceName,
		TargetPath:    m.executablePath,
		StagePath:     paths.Stage,
		BackupPath:    paths.Backup,
		RecoveryPath:  paths.Recovery,
		PlanPath:      paths.Plan,
		ReadyPath:     paths.Ready,
		ProceedPath:   paths.Proceed,
		StatePath:     paths.State,
		ParentPID:     os.Getpid(),
		ParentStarted: parentStarted,
		ListenAddress: listenAddress,
		Version:       version,
		OldVersion:    m.currentVersion,
		OldSHA256:     oldHash,
		NewSHA256:     newHash,
		UpdateToken:   token,
		TransactionID: transactionID,
		LegacyHealth:  release.Verification == "legacy",
		CreatedAt:     time.Now().UTC(),
	}
	if err := writeJSONAtomic(paths.Plan, plan); err != nil {
		_ = os.Remove(paths.Stage)
		m.fail(version, fmt.Errorf("write update plan: %w", err))
		return
	}
	restarting := Status{Phase: PhaseRestarting, Busy: true, Version: version, TransactionID: plan.TransactionID, Message: "Перезапуск приложения…", DownloadedBytes: release.Size, TotalBytes: release.Size, UpdatedAt: time.Now().UTC()}
	m.setStatus(restarting)
	m.mu.Lock()
	m.stateReload = true
	m.mu.Unlock()
	if err := writeJSONAtomic(paths.State, restarting); err != nil {
		_ = os.Remove(paths.Plan)
		_ = os.Remove(paths.Stage)
		m.fail(version, fmt.Errorf("record update transaction: %w", err))
		return
	}
	releaseLock := func() (bool, error) {
		m.mu.Lock()
		lock := m.updateLock
		m.mu.Unlock()
		if lock == nil {
			return false, errors.New("update transaction lock is unavailable")
		}
		released, err := lock.ReleaseForHandoff()
		m.mu.Lock()
		if released && m.updateLock == lock {
			m.updateLock = nil
			m.lockHandoff = true
		}
		m.mu.Unlock()
		return released, err
	}
	if err := m.handoff(plan, releaseLock); err != nil {
		m.mu.Lock()
		handedOff := m.lockHandoff
		m.mu.Unlock()
		if handedOff && errors.Is(err, errHandoffPossiblyCommitted) {
			// Permission is an irreversible boundary: if the helper cannot be
			// confirmed dead, it may still stop this process and finish the
			// transaction. Keep the persisted restarting state instead of
			// reporting a false terminal failure. Status reconciliation will
			// resolve the transaction once the helper releases the lock.
			return
		}
		failure := fmt.Errorf("start update helper: %w", err)
		if handedOff {
			// The helper (or a successor) may own these fixed transaction paths.
			// Leave every shared artifact untouched until reconciliation obtains the lock.
			m.setStatus(Status{Phase: PhaseFailed, Version: version, TransactionID: plan.TransactionID, Error: failure.Error(), UpdatedAt: time.Now().UTC()})
		} else {
			failed := Status{Phase: PhaseFailed, Version: version, TransactionID: plan.TransactionID, Error: failure.Error(), UpdatedAt: time.Now().UTC()}
			if m.invalidatePreparedTransaction(plan, paths, failed) {
				_ = os.Remove(paths.Stage)
				_ = os.Remove(paths.Ready)
				_ = os.Remove(paths.Proceed)
			} else {
				failed.Error += "; active transaction could not be invalidated, so its lock is retained"
				m.mu.Lock()
				m.lockRetained = true
				m.mu.Unlock()
			}
			m.setStatus(failed)
		}
		return
	}
	if m.customHandoff {
		_ = os.Remove(filepath.Join(m.directory, lockFileName))
	}
	m.stopFunc()
}

func (m *Manager) invalidatePreparedTransaction(plan HandoffPlan, paths transactionPaths, failed Status) bool {
	if err := writeJSONAtomic(paths.State, failed); err == nil {
		return true
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := os.Remove(paths.Plan)
		if err == nil || errors.Is(err, os.ErrNotExist) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (m *Manager) resolveRelease(ctx context.Context, version string) (Release, error) {
	m.mu.Lock()
	cached := append([]Release(nil), m.cache...)
	cacheFresh := time.Since(m.cacheAt) < 5*time.Minute
	m.mu.Unlock()
	if !cacheFresh {
		var err error
		cached, err = m.source.ListReleases(ctx)
		if err != nil {
			return Release{}, err
		}
		cached = limitVisibleReleases(cached)
		m.mu.Lock()
		m.cache = append(m.cache[:0], cached...)
		m.cacheAt = time.Now().UTC()
		m.mu.Unlock()
	}
	for _, release := range cached {
		if release.Version == version {
			return release, nil
		}
	}
	return Release{}, fmt.Errorf("release %s is not among the five latest published releases", version)
}

func (m *Manager) Status() Status {
	m.reloadPersistedStatus()
	m.reconcileTransaction(false)
	m.reloadPersistedStatus()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

func (m *Manager) reloadPersistedStatus() {
	m.mu.Lock()
	status := m.status
	shouldReload := m.stateReload && status.Phase == PhaseRestarting
	m.mu.Unlock()
	if shouldReload {
		var persisted Status
		if err := readBoundedJSON(filepath.Join(m.directory, stateFileName), &persisted, 64<<10); err == nil && persisted.Phase != "" {
			m.mu.Lock()
			if persisted.UpdatedAt.After(m.status.UpdatedAt) {
				m.status = persisted
			}
			if persisted.Phase != PhaseRestarting {
				m.stateReload = false
			}
			status = m.status
			m.mu.Unlock()
		}
	}
}

func (m *Manager) reconcileTransaction(force bool) {
	m.mu.Lock()
	if m.active || m.closed || m.customHandoff || m.lockRetained {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	paths := updatePaths(m.directory)
	if _, err := os.Stat(paths.Plan); errors.Is(err, os.ErrNotExist) {
		m.mu.Lock()
		needsNormalization := m.status.Phase == PhaseRestarting
		m.mu.Unlock()
		if !needsNormalization {
			return
		}
	} else if err != nil {
		return
	}
	lock, err := acquireUpdateLock(m.executablePath)
	if err != nil {
		return
	}
	defer lock.Close()
	planInfo, err := os.Stat(paths.Plan)
	if errors.Is(err, os.ErrNotExist) {
		m.adoptPersistedTerminalState(paths.State)
		m.normalizeMissingTransactionPlan()
		return
	}
	if err != nil {
		return
	}
	fingerprint := fmt.Sprintf("%d:%d", planInfo.Size(), planInfo.ModTime().UnixNano())
	if !force && m.reconciliationMemoMatches(fingerprint) {
		return
	}
	var plan HandoffPlan
	if err := readBoundedJSON(paths.Plan, &plan, 64<<10); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			m.adoptPersistedTerminalState(paths.State)
			m.normalizeMissingTransactionPlan()
			return
		}
		m.setReconcileFailure("Незавершённое обновление имеет повреждённый план")
		m.rememberReconciliation(fingerprint)
		return
	}
	if plan.Format != handoffPlanFormat || plan.FormatVersion != 2 || !strings.EqualFold(plan.TargetPath, m.executablePath) ||
		!strings.EqualFold(plan.StagePath, paths.Stage) || !strings.EqualFold(plan.BackupPath, paths.Backup) ||
		!strings.EqualFold(plan.RecoveryPath, paths.Recovery) || !strings.EqualFold(plan.PlanPath, paths.Plan) ||
		!strings.EqualFold(plan.ReadyPath, paths.Ready) || !strings.EqualFold(plan.ProceedPath, paths.Proceed) || !strings.EqualFold(plan.StatePath, paths.State) {
		m.setReconcileFailure("Незавершённое обновление содержит небезопасные пути")
		m.rememberReconciliation(fingerprint)
		return
	}
	targetHash, err := hashFile(m.executablePath)
	if err != nil {
		m.setReconcileFailure("Не удалось проверить исполняемый файл незавершённого обновления")
		m.rememberReconciliation(fingerprint)
		return
	}
	var persisted Status
	persistedErr := readBoundedJSON(paths.State, &persisted, 64<<10)
	var status Status
	switch {
	case strings.EqualFold(targetHash, plan.NewSHA256) && m.currentVersion == plan.Version:
		if persistedErr != nil || persisted.Phase != PhaseSucceeded || persisted.Busy || persisted.Version != plan.Version ||
			persisted.TransactionID != plan.TransactionID || persisted.UpdatedAt.Before(plan.CreatedAt) {
			m.setReconcileFailure("Новая версия запущена, но helper не подтвердил завершение; резервная копия сохранена для ручного восстановления")
			m.rememberReconciliation(fingerprint)
			return
		}
		status = persisted
		status.Message = "Обновление завершено; служебные файлы очищены после прерывания helper"
		status.UpdatedAt = time.Now().UTC()
	case strings.EqualFold(targetHash, plan.OldSHA256) && m.currentVersion == plan.OldVersion:
		status = Status{Phase: PhaseFailed, Version: plan.Version, TransactionID: plan.TransactionID, Error: "Предыдущее обновление было прервано; сохранена прежняя рабочая версия", UpdatedAt: time.Now().UTC()}
		if err := m.syncTarget(m.executablePath); err != nil {
			status.Error += "; не удалось синхронизировать исполняемый файл, поэтому резервные копии сохранены: " + err.Error()
			_ = writeJSONAtomic(paths.State, status)
			m.mu.Lock()
			m.status = status
			m.stateReload = false
			m.mu.Unlock()
			m.rememberReconciliation(fingerprint)
			return
		}
	default:
		m.setReconcileFailure("Состояние незавершённого обновления неоднозначно; автоматическая очистка отменена")
		m.rememberReconciliation(fingerprint)
		return
	}
	if status.Phase == PhaseFailed {
		if err := writeJSONAtomic(paths.State, status); err != nil {
			m.mu.Lock()
			m.status = status
			m.stateReload = false
			m.mu.Unlock()
			m.rememberReconciliation(fingerprint)
			return
		}
	}
	if err := cleanupRecoveredTransaction(paths); err != nil {
		status.Message = "Приложение работает, но часть служебных файлов обновления не удалось удалить"
		if status.Phase == PhaseFailed {
			status.Error += "; " + err.Error()
		}
		m.rememberReconciliation(fingerprint)
	}
	_ = writeJSONAtomic(paths.State, status)
	m.mu.Lock()
	m.status = status
	m.stateReload = false
	m.healthToken = ""
	m.mu.Unlock()
}

func (m *Manager) reconciliationMemoMatches(fingerprint string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fingerprint != "" && m.reconcileMemo == fingerprint
}

func (m *Manager) rememberReconciliation(fingerprint string) {
	if fingerprint == "" {
		return
	}
	m.mu.Lock()
	m.reconcileMemo = fingerprint
	m.mu.Unlock()
}

func (m *Manager) adoptPersistedTerminalState(path string) {
	var status Status
	if err := readBoundedJSON(path, &status, 64<<10); err != nil || status.Busy || (status.Phase != PhaseSucceeded && status.Phase != PhaseFailed) {
		return
	}
	m.mu.Lock()
	if m.status.UpdatedAt.Before(status.UpdatedAt) || m.status.Phase == PhaseRestarting {
		m.status = status
		m.stateReload = false
	}
	m.mu.Unlock()
}

func (m *Manager) normalizeMissingTransactionPlan() {
	m.mu.Lock()
	if m.status.Phase != PhaseRestarting {
		m.mu.Unlock()
		return
	}
	status := Status{
		Phase:     PhaseFailed,
		Version:   m.status.Version,
		Error:     "План обновления отсутствует, поэтому результат установки не подтверждён; текущее приложение продолжает работу",
		UpdatedAt: time.Now().UTC(),
	}
	m.status = status
	m.stateReload = false
	m.healthToken = ""
	m.mu.Unlock()
	_ = writeJSONAtomic(filepath.Join(m.directory, stateFileName), status)
}

func (m *Manager) setReconcileFailure(message string) {
	status := Status{Phase: PhaseFailed, Error: message, UpdatedAt: time.Now().UTC()}
	_ = writeJSONAtomic(filepath.Join(m.directory, stateFileName), status)
	m.mu.Lock()
	m.status = status
	m.stateReload = false
	m.mu.Unlock()
}

func cleanupRecoveredTransaction(paths transactionPaths) error {
	var failures []string
	for _, path := range []string{paths.Stage, paths.Stage + ".part", paths.Backup, paths.Recovery, paths.Ready, paths.Proceed} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, filepath.Base(path)+": "+err.Error())
		}
	}
	if len(failures) == 0 {
		if err := os.Remove(paths.Plan); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, filepath.Base(paths.Plan)+": "+err.Error())
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (m *Manager) HealthToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.healthToken == "" {
		return ""
	}
	if _, err := os.Stat(filepath.Join(m.directory, planFileName)); errors.Is(err, os.ErrNotExist) {
		m.healthToken = ""
		return ""
	}
	return m.healthToken
}

func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.maintenanceOnce.Do(func() { close(m.maintenanceStop) })
	if m.cancel != nil && m.status.Phase != PhaseRestarting {
		m.cancel()
	}
	m.mu.Unlock()
	m.wg.Wait()
	m.maintenanceWG.Wait()
}

func (m *Manager) setStatus(status Status) {
	m.mu.Lock()
	m.status = status
	m.mu.Unlock()
}

func (m *Manager) fail(version string, err error) {
	status := Status{Phase: PhaseFailed, Version: version, Error: err.Error(), UpdatedAt: time.Now().UTC()}
	m.setStatus(status)
	_ = writeJSONAtomic(filepath.Join(m.directory, stateFileName), status)
}

func (m *Manager) loadPersistedState() {
	var status Status
	if err := readBoundedJSON(filepath.Join(m.directory, stateFileName), &status, 64<<10); err != nil {
		return
	}
	if status.UpdatedAt.IsZero() || time.Since(status.UpdatedAt) > 24*time.Hour || time.Until(status.UpdatedAt) > 5*time.Minute {
		return
	}
	m.status = status
	m.status.Busy = false
	if status.Phase == PhaseRestarting {
		m.status.Busy = true
		m.stateReload = true
	}
}

func (m *Manager) loadHealthToken() {
	var plan HandoffPlan
	if err := readBoundedJSON(filepath.Join(m.directory, planFileName), &plan, 64<<10); err != nil {
		return
	}
	if plan.Format != handoffPlanFormat || plan.FormatVersion != 2 || !strings.EqualFold(plan.TargetPath, m.executablePath) || plan.Version != m.currentVersion ||
		len(plan.UpdateToken) != 64 {
		return
	}
	if _, err := hex.DecodeString(plan.UpdateToken); err != nil {
		return
	}
	transactionID, err := transactionIDForToken(plan.UpdateToken)
	if err != nil || plan.TransactionID != transactionID {
		return
	}
	if time.Since(plan.CreatedAt) < 0 || time.Since(plan.CreatedAt) > 10*time.Minute {
		return
	}
	m.healthToken = plan.UpdateToken
}

type transactionPaths struct {
	Stage    string
	Backup   string
	Recovery string
	Plan     string
	Ready    string
	Proceed  string
	State    string
}

func updatePaths(directory string) transactionPaths {
	return transactionPaths{
		Stage: filepath.Join(directory, stageFileName), Backup: filepath.Join(directory, backupFileName), Recovery: filepath.Join(directory, recoveryFileName),
		Plan: filepath.Join(directory, planFileName), Ready: filepath.Join(directory, readyFileName), Proceed: filepath.Join(directory, proceedFileName),
		State: filepath.Join(directory, stateFileName),
	}
}

func prepareTransactionPaths(paths transactionPaths) error {
	for _, path := range []string{paths.Backup, paths.Recovery, paths.Plan} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("unfinished update transaction contains %s", filepath.Base(path))
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, path := range []string{paths.Stage, paths.Stage + ".part", paths.Ready, paths.Proceed} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale update file %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if err := platformcrypto.Random(value); err != nil {
		return "", fmt.Errorf("generate update token: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func transactionIDForToken(token string) (string, error) {
	digest, err := platformcrypto.SHA256([]byte(token))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash, err := platformcrypto.NewSHA256()
	if err != nil {
		return "", err
	}
	defer hash.Close()
	if _, err := io.CopyBuffer(hash, file, make([]byte, 64<<10)); err != nil {
		return "", err
	}
	digest, err := hash.Sum()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func writeJSONAtomic(path string, value any) error {
	content, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := replacePath(temporary, path); err != nil {
		return err
	}
	remove = false
	return nil
}

func readBoundedJSON(path string, target any, limit int64) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return err
	}
	if int64(len(content)) > limit {
		return errors.New("JSON file exceeds limit")
	}
	return json.Unmarshal(content, target)
}
