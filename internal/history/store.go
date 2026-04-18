package history

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openai/pitchprox/internal/config"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB

	mu                 sync.Mutex
	pendingLogs        []LogRecord
	pendingConnections []ConnectionRecord
	pendingTraffic     map[int64]TrafficSample
	pendingRule        map[string]rulePending
	retention          atomic.Int64
	lastPrune          time.Time
	wake               chan struct{}
	stop               chan struct{}
	wg                 sync.WaitGroup
}

type rulePending struct {
	Ts   int64
	Item RuleActivity
}

const (
	flushInterval      = 3 * time.Second
	pruneInterval      = time.Minute
	maxInitialLogQuery = 5000
)

func Open(path string, retention time.Duration) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create history dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	s := &Store{
		db:             db,
		pendingTraffic: map[int64]TrafficSample{},
		pendingRule:    map[string]rulePending{},
		wake:           make(chan struct{}, 1),
		stop:           make(chan struct{}),
	}
	s.SetRetentionWindow(retention)
	if err := s.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	s.wg.Add(1)
	go s.loop()
	return s, nil
}

func (s *Store) Close() error {
	close(s.stop)
	s.wg.Wait()
	return s.db.Close()
}

func (s *Store) SetRetentionWindow(d time.Duration) {
	if d < time.Minute {
		d = 7 * time.Minute
	}
	s.retention.Store(int64(d))
	s.wakeFlush()
}

func (s *Store) RecordLog(entry LogRecord) {
	s.mu.Lock()
	s.pendingLogs = append(s.pendingLogs, entry)
	count := len(s.pendingLogs)
	s.mu.Unlock()
	if count >= 64 {
		s.wakeFlush()
	}
}

func (s *Store) RecordConnection(entry ConnectionRecord) {
	s.mu.Lock()
	s.pendingConnections = append(s.pendingConnections, entry)
	count := len(s.pendingConnections)
	s.mu.Unlock()
	if count >= 64 {
		s.wakeFlush()
	}
}

func (s *Store) AddTraffic(ts time.Time, upBytes, downBytes int64) {
	if upBytes == 0 && downBytes == 0 {
		return
	}
	bucket := ts.UTC().Truncate(time.Second)
	key := bucket.Unix()
	s.mu.Lock()
	item := s.pendingTraffic[key]
	if item.Time.IsZero() {
		item.Time = bucket
	}
	item.UpBytes += upBytes
	item.DownBytes += downBytes
	s.pendingTraffic[key] = item
	s.mu.Unlock()
}

func (s *Store) AddRuleActivity(ts time.Time, ruleID, ruleName string, action config.RuleAction, conns, upBytes, downBytes int64) {
	if strings.TrimSpace(ruleID) == "" && strings.TrimSpace(ruleName) == "" {
		return
	}
	if conns == 0 && upBytes == 0 && downBytes == 0 {
		return
	}
	bucket := ts.UTC().Truncate(time.Second)
	key := fmt.Sprintf("%d\x1f%s\x1f%s\x1f%s", bucket.Unix(), strings.ToLower(strings.TrimSpace(ruleID)), strings.ToLower(strings.TrimSpace(ruleName)), strings.ToLower(strings.TrimSpace(string(action))))
	s.mu.Lock()
	item := s.pendingRule[key]
	item.Ts = bucket.Unix()
	if item.Item.RuleID == "" {
		item.Item.RuleID = ruleID
		item.Item.RuleName = ruleName
		item.Item.Action = action
	}
	item.Item.Connections += conns
	item.Item.UpBytes += upBytes
	item.Item.DownBytes += downBytes
	s.pendingRule[key] = item
	s.mu.Unlock()
}

func (s *Store) Snapshot(retention time.Duration) (SnapshotData, error) {
	if retention < time.Minute {
		retention = time.Duration(s.retention.Load())
	}
	if err := s.Flush(); err != nil {
		return SnapshotData{}, err
	}
	cutoff := time.Now().UTC().Add(-retention)
	out := SnapshotData{}
	var err error
	if out.Connections, err = s.queryConnections(cutoff); err != nil {
		return SnapshotData{}, err
	}
	if out.Logs, err = s.queryLogs(cutoff); err != nil {
		return SnapshotData{}, err
	}
	if out.Traffic, out.TrafficTotals, err = s.queryTraffic(cutoff); err != nil {
		return SnapshotData{}, err
	}
	if out.RuleStats, err = s.queryRuleStats(cutoff); err != nil {
		return SnapshotData{}, err
	}
	return out, nil
}

func (s *Store) Flush() error {
	s.mu.Lock()
	logs := append([]LogRecord(nil), s.pendingLogs...)
	conns := append([]ConnectionRecord(nil), s.pendingConnections...)
	traffic := s.pendingTraffic
	rules := s.pendingRule
	if len(logs) == 0 && len(conns) == 0 && len(traffic) == 0 && len(rules) == 0 && time.Since(s.lastPrune) < pruneInterval {
		s.mu.Unlock()
		return nil
	}
	s.pendingLogs = nil
	s.pendingConnections = nil
	s.pendingTraffic = map[int64]TrafficSample{}
	s.pendingRule = map[string]rulePending{}
	shouldPrune := time.Since(s.lastPrune) >= pruneInterval
	if shouldPrune {
		s.lastPrune = time.Now().UTC()
	}
	s.mu.Unlock()

	if len(logs) == 0 && len(conns) == 0 && len(traffic) == 0 && len(rules) == 0 && !shouldPrune {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin history tx: %w", err)
	}
	rollback := func(e error) error {
		_ = tx.Rollback()
		return e
	}

	if len(logs) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO logs(ts, level, message, connection_id, pid, exe_path, action, rule_id, rule_name, host, port)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return rollback(fmt.Errorf("prepare log insert: %w", err))
		}
		for _, item := range logs {
			if _, err := stmt.Exec(item.Time.UTC().UnixMilli(), item.Level, item.Message, item.ConnectionID, item.PID, item.ExePath, string(item.Action), item.RuleID, item.RuleName, item.Host, item.Port); err != nil {
				_ = stmt.Close()
				return rollback(fmt.Errorf("insert log: %w", err))
			}
		}
		_ = stmt.Close()
	}

	if len(conns) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO connection_history(
			connection_id, pid, exe_path, source_ip, source_port, original_ip, original_port, hostname,
			rule_id, rule_name, action, proxy_id, chain_id, state, bytes_up, bytes_down,
			created_at, last_updated_at, hit_count)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return rollback(fmt.Errorf("prepare connection insert: %w", err))
		}
		for _, item := range conns {
			count := item.Count
			if count <= 0 {
				count = 1
			}
			created := item.CreatedAt.UTC()
			if created.IsZero() {
				created = time.Now().UTC()
			}
			updated := item.LastUpdatedAt.UTC()
			if updated.IsZero() {
				updated = created
			}
			if _, err := stmt.Exec(item.ID, item.PID, item.ExePath, item.SourceIP, item.SourcePort, item.OriginalIP, item.OriginalPort, item.Hostname,
				item.RuleID, item.RuleName, string(item.Action), item.ProxyID, item.ChainID, item.State, item.BytesUp, item.BytesDown,
				created.UnixMilli(), updated.UnixMilli(), count); err != nil {
				_ = stmt.Close()
				return rollback(fmt.Errorf("insert connection: %w", err))
			}
		}
		_ = stmt.Close()
	}

	if len(traffic) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO traffic_seconds(ts, up_bytes, down_bytes)
			VALUES(?, ?, ?)
			ON CONFLICT(ts) DO UPDATE SET up_bytes = up_bytes + excluded.up_bytes, down_bytes = down_bytes + excluded.down_bytes`)
		if err != nil {
			return rollback(fmt.Errorf("prepare traffic upsert: %w", err))
		}
		keys := make([]int64, 0, len(traffic))
		for ts := range traffic {
			keys = append(keys, ts)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, ts := range keys {
			item := traffic[ts]
			if _, err := stmt.Exec(ts, item.UpBytes, item.DownBytes); err != nil {
				_ = stmt.Close()
				return rollback(fmt.Errorf("upsert traffic: %w", err))
			}
		}
		_ = stmt.Close()
	}

	if len(rules) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO rule_activity_seconds(ts, rule_id, rule_name, action, connections, up_bytes, down_bytes)
			VALUES(?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(ts, rule_id, rule_name, action)
			DO UPDATE SET connections = connections + excluded.connections, up_bytes = up_bytes + excluded.up_bytes, down_bytes = down_bytes + excluded.down_bytes`)
		if err != nil {
			return rollback(fmt.Errorf("prepare rule activity upsert: %w", err))
		}
		keys := make([]string, 0, len(rules))
		for key := range rules {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			item := rules[key]
			if _, err := stmt.Exec(item.Ts, item.Item.RuleID, item.Item.RuleName, string(item.Item.Action), item.Item.Connections, item.Item.UpBytes, item.Item.DownBytes); err != nil {
				_ = stmt.Close()
				return rollback(fmt.Errorf("upsert rule activity: %w", err))
			}
		}
		_ = stmt.Close()
	}

	if shouldPrune {
		cutoff := time.Now().UTC().Add(-time.Duration(s.retention.Load())).UnixMilli()
		for _, query := range []string{
			`DELETE FROM logs WHERE ts < ?`,
			`DELETE FROM connection_history WHERE last_updated_at < ?`,
			`DELETE FROM traffic_seconds WHERE ts * 1000 < ?`,
			`DELETE FROM rule_activity_seconds WHERE ts * 1000 < ?`,
		} {
			if _, err := tx.Exec(query, cutoff); err != nil {
				return rollback(fmt.Errorf("prune history: %w", err))
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit history tx: %w", err)
	}
	return nil
}

func (s *Store) loop() {
	defer s.wg.Done()
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			_ = s.Flush()
			return
		case <-ticker.C:
			_ = s.Flush()
		case <-s.wake:
			_ = s.Flush()
		}
	}
}

func (s *Store) wakeFlush() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Store) init() error {
	pragmas := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`PRAGMA temp_store=MEMORY;`,
		`PRAGMA busy_timeout=5000;`,
	}
	for _, q := range pragmas {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("sqlite pragma: %w", err)
		}
	}
	schema := []string{
		`CREATE TABLE IF NOT EXISTS logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts INTEGER NOT NULL,
			level TEXT NOT NULL,
			message TEXT NOT NULL,
			connection_id TEXT,
			pid INTEGER,
			exe_path TEXT,
			action TEXT,
			rule_id TEXT,
			rule_name TEXT,
			host TEXT,
			port INTEGER
		);`,
		`CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_logs_pid_ts ON logs(pid, ts DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_logs_action_ts ON logs(action, ts DESC);`,
		`CREATE TABLE IF NOT EXISTS connection_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			connection_id TEXT,
			pid INTEGER NOT NULL,
			exe_path TEXT,
			source_ip TEXT,
			source_port INTEGER,
			original_ip TEXT,
			original_port INTEGER,
			hostname TEXT,
			rule_id TEXT,
			rule_name TEXT,
			action TEXT,
			proxy_id TEXT,
			chain_id TEXT,
			state TEXT,
			bytes_up INTEGER NOT NULL DEFAULT 0,
			bytes_down INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			last_updated_at INTEGER NOT NULL,
			hit_count INTEGER NOT NULL DEFAULT 1
		);`,
		`CREATE INDEX IF NOT EXISTS idx_connection_history_last ON connection_history(last_updated_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_connection_history_rule ON connection_history(rule_id, last_updated_at DESC);`,
		`CREATE INDEX IF NOT EXISTS idx_connection_history_pid ON connection_history(pid, last_updated_at DESC);`,
		`CREATE TABLE IF NOT EXISTS traffic_seconds (
			ts INTEGER PRIMARY KEY,
			up_bytes INTEGER NOT NULL DEFAULT 0,
			down_bytes INTEGER NOT NULL DEFAULT 0
		);`,
		`CREATE TABLE IF NOT EXISTS rule_activity_seconds (
			ts INTEGER NOT NULL,
			rule_id TEXT NOT NULL DEFAULT '',
			rule_name TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL DEFAULT '',
			connections INTEGER NOT NULL DEFAULT 0,
			up_bytes INTEGER NOT NULL DEFAULT 0,
			down_bytes INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(ts, rule_id, rule_name, action)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_rule_activity_ts ON rule_activity_seconds(ts DESC);`,
	}
	for _, q := range schema {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}
	return nil
}

func (s *Store) queryConnections(cutoff time.Time) ([]ConnectionRecord, error) {
	rows, err := s.db.Query(`SELECT
		COALESCE(MAX(connection_id), ''),
		pid,
		COALESCE(exe_path, ''),
		COALESCE(MAX(source_ip), ''),
		COALESCE(MAX(source_port), 0),
		COALESCE(original_ip, ''),
		COALESCE(original_port, 0),
		COALESCE(hostname, ''),
		COALESCE(rule_id, ''),
		COALESCE(rule_name, ''),
		COALESCE(action, ''),
		COALESCE(proxy_id, ''),
		COALESCE(chain_id, ''),
		CASE
			WHEN SUM(CASE WHEN state = 'blocked' THEN 1 ELSE 0 END) = COUNT(*) THEN 'blocked'
			WHEN SUM(CASE WHEN state = 'error' THEN 1 ELSE 0 END) > 0 THEN 'error'
			ELSE 'closed'
		END,
		SUM(bytes_up),
		SUM(bytes_down),
		MIN(created_at),
		MAX(last_updated_at),
		SUM(hit_count)
	FROM connection_history
	WHERE last_updated_at >= ?
	GROUP BY pid, exe_path, original_ip, original_port, hostname, rule_id, rule_name, action, proxy_id, chain_id
	ORDER BY MAX(last_updated_at) DESC`, cutoff.UTC().UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("query connections: %w", err)
	}
	defer rows.Close()
	out := make([]ConnectionRecord, 0, 64)
	for rows.Next() {
		var item ConnectionRecord
		var action string
		var createdMs, updatedMs int64
		if err := rows.Scan(&item.ID, &item.PID, &item.ExePath, &item.SourceIP, &item.SourcePort, &item.OriginalIP, &item.OriginalPort, &item.Hostname, &item.RuleID, &item.RuleName, &action, &item.ProxyID, &item.ChainID, &item.State, &item.BytesUp, &item.BytesDown, &createdMs, &updatedMs, &item.Count); err != nil {
			return nil, fmt.Errorf("scan connection: %w", err)
		}
		item.Action = config.RuleAction(action)
		item.CreatedAt = time.UnixMilli(createdMs).UTC()
		item.LastUpdatedAt = time.UnixMilli(updatedMs).UTC()
		if item.Count <= 0 {
			item.Count = 1
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) queryLogs(cutoff time.Time) ([]LogRecord, error) {
	rows, err := s.db.Query(`SELECT ts, level, message, connection_id, pid, exe_path, action, rule_id, rule_name, host, port
		FROM logs
		WHERE ts >= ?
		ORDER BY ts DESC
		LIMIT ?`, cutoff.UTC().UnixMilli(), maxInitialLogQuery)
	if err != nil {
		return nil, fmt.Errorf("query logs: %w", err)
	}
	defer rows.Close()
	items := make([]LogRecord, 0, 128)
	for rows.Next() {
		var item LogRecord
		var action string
		var ts int64
		if err := rows.Scan(&ts, &item.Level, &item.Message, &item.ConnectionID, &item.PID, &item.ExePath, &action, &item.RuleID, &item.RuleName, &item.Host, &item.Port); err != nil {
			return nil, fmt.Errorf("scan log: %w", err)
		}
		item.Time = time.UnixMilli(ts).UTC()
		item.Action = config.RuleAction(action)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return trimLogs(items), nil
}

func (s *Store) queryTraffic(cutoff time.Time) ([]TrafficSample, TrafficTotals, error) {
	rows, err := s.db.Query(`SELECT ts, up_bytes, down_bytes FROM traffic_seconds WHERE ts >= ? ORDER BY ts ASC`, cutoff.UTC().Unix())
	if err != nil {
		return nil, TrafficTotals{}, fmt.Errorf("query traffic: %w", err)
	}
	defer rows.Close()
	out := make([]TrafficSample, 0, 256)
	totals := TrafficTotals{}
	for rows.Next() {
		var ts int64
		var item TrafficSample
		if err := rows.Scan(&ts, &item.UpBytes, &item.DownBytes); err != nil {
			return nil, TrafficTotals{}, fmt.Errorf("scan traffic: %w", err)
		}
		item.Time = time.Unix(ts, 0).UTC()
		totals.UpBytes += item.UpBytes
		totals.DownBytes += item.DownBytes
		out = append(out, item)
	}
	return out, totals, rows.Err()
}

func (s *Store) queryRuleStats(cutoff time.Time) ([]RuleActivity, error) {
	rows, err := s.db.Query(`SELECT rule_id, rule_name, action, SUM(connections), SUM(up_bytes), SUM(down_bytes)
		FROM rule_activity_seconds
		WHERE ts >= ?
		GROUP BY rule_id, rule_name, action`, cutoff.UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("query rule stats: %w", err)
	}
	defer rows.Close()
	out := make([]RuleActivity, 0, 64)
	for rows.Next() {
		var item RuleActivity
		var action string
		if err := rows.Scan(&item.RuleID, &item.RuleName, &action, &item.Connections, &item.UpBytes, &item.DownBytes); err != nil {
			return nil, fmt.Errorf("scan rule stat: %w", err)
		}
		item.Action = config.RuleAction(action)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Connections != out[j].Connections {
			return out[i].Connections > out[j].Connections
		}
		ai := out[i].UpBytes + out[i].DownBytes
		aj := out[j].UpBytes + out[j].DownBytes
		if ai != aj {
			return ai > aj
		}
		return strings.ToLower(out[i].RuleName) < strings.ToLower(out[j].RuleName)
	})
	return out, nil
}

func trimLogs(items []LogRecord) []LogRecord {
	if len(items) == 0 {
		return nil
	}
	const (
		processKeep = 100
		genericKeep = 200
	)
	perProcess := map[uint32]int{}
	genericCount := 0
	kept := make([]LogRecord, 0, len(items))
	for _, item := range items {
		if item.PID != 0 {
			if perProcess[item.PID] >= processKeep {
				continue
			}
			perProcess[item.PID]++
		} else {
			if genericCount >= genericKeep {
				continue
			}
			genericCount++
		}
		kept = append(kept, item)
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Time.Before(kept[j].Time) })
	return kept
}
