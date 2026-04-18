package util

import (
	"os"
	"path/filepath"
	"runtime"
)

const (
	portableConfigName       = "pitchProx.config.json"
	portableHistoryName      = "pitchProx.history.sqlite"
	legacyPortableConfigName = "myprox.config.json"
	legacyPortableHistory    = "myprox.history.sqlite"
)

func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		if base := os.Getenv("ProgramData"); base != "" {
			return filepath.Join(base, "pitchProx")
		}
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "pitchprox")
	}
	return filepath.Join(os.TempDir(), "pitchprox")
}

func ConfigPath() string {
	if override := os.Getenv("PITCHPROX_CONFIG"); override != "" {
		return override
	}
	if override := os.Getenv("MYPROX_CONFIG"); override != "" {
		return override
	}
	if exe, err := os.Executable(); err == nil {
		portable := filepath.Join(filepath.Dir(exe), portableConfigName)
		migrateLegacyFile(portable, legacyConfigCandidates())
		return portable
	}
	return filepath.Join(DefaultDataDir(), "config.json")
}

func HistoryPath() string {
	if override := os.Getenv("PITCHPROX_HISTORY"); override != "" {
		return override
	}
	if override := os.Getenv("MYPROX_HISTORY"); override != "" {
		return override
	}
	if exe, err := os.Executable(); err == nil {
		portable := filepath.Join(filepath.Dir(exe), portableHistoryName)
		migrateLegacyFile(portable, legacyHistoryCandidates())
		return portable
	}
	return filepath.Join(DefaultDataDir(), portableHistoryName)
}

func migrateLegacyFile(dst string, legacyCandidates []string) {
	if _, err := os.Stat(dst); err == nil {
		return
	}
	for _, legacy := range legacyCandidates {
		data, err := os.ReadFile(legacy)
		if err != nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return
		}
		_ = os.WriteFile(dst, data, 0o644)
		return
	}
}

func legacyConfigCandidates() []string {
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), legacyPortableConfigName))
	}
	if runtime.GOOS == "windows" {
		if base := os.Getenv("ProgramData"); base != "" {
			candidates = append(candidates,
				filepath.Join(base, "pitchProx", "config.json"),
				filepath.Join(base, "MyProx", "config.json"),
			)
		}
	}
	if dir, err := os.UserConfigDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(dir, "pitchprox", "config.json"),
			filepath.Join(dir, "myprox", "config.json"),
		)
	}
	return candidates
}

func legacyHistoryCandidates() []string {
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), legacyPortableHistory))
	}
	if runtime.GOOS == "windows" {
		if base := os.Getenv("ProgramData"); base != "" {
			candidates = append(candidates,
				filepath.Join(base, "pitchProx", "history.sqlite"),
				filepath.Join(base, "MyProx", "history.sqlite"),
			)
		}
	}
	if dir, err := os.UserConfigDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(dir, "pitchprox", "history.sqlite"),
			filepath.Join(dir, "myprox", "history.sqlite"),
		)
	}
	return candidates
}
