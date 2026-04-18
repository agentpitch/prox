package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	path string
	mu   sync.RWMutex
	cfg  Config
}

func NewStore(path string) (*Store, error) {
	st := &Store{path: path}
	if err := st.LoadOrCreate(); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Store) Path() string { return s.path }

func (s *Store) LoadOrCreate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.cfg = DefaultConfig()
		Normalize(&s.cfg)
		return s.saveLocked()
	}
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	Normalize(&cfg)
	if err := Validate(cfg); err != nil {
		return fmt.Errorf("validate config: %w", err)
	}
	s.cfg = cfg
	return nil
}

func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneConfig(s.cfg)
}

func (s *Store) Save(cfg Config) error {
	Normalize(&cfg)
	if err := Validate(cfg); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg.UpdatedAt = time.Now().UTC()
	s.cfg = cloneConfig(cfg)
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write tmp config: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

func cloneConfig(cfg Config) Config {
	out := cfg
	out.Proxies = append([]ProxyProfile(nil), cfg.Proxies...)
	out.Chains = make([]ProxyChain, len(cfg.Chains))
	copy(out.Chains, cfg.Chains)
	for i := range out.Chains {
		out.Chains[i].ProxyIDs = append([]string(nil), cfg.Chains[i].ProxyIDs...)
	}
	out.Rules = append([]Rule(nil), cfg.Rules...)
	return out
}
