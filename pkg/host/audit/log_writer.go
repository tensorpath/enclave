package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "modernc.org/sqlite"

	"enclave/pkg/shared/logger"
)

var log = logger.New(os.Stdout)

// AsyncLogWriter handles buffered writing of audit logs to Postgres.
type AsyncLogWriter struct {
	pool          *pgxpool.Pool
	sqlite        *sql.DB
	dbURL         string
	backend       string
	logCh         chan *Entry
	batchSize     int
	flushInterval time.Duration
	hub           *Hub
	mu            sync.RWMutex
	connected     bool
	lastError     string
}

// Entry allows logging generic events.
type Entry struct {
	SessionID string
	Timestamp time.Time
	Action    string
	Status    string
	Input     string
	Output    string
	Metadata  map[string]interface{}
}

// NewAsyncLogWriter creates a new writer.
func NewAsyncLogWriter(dbURL string) *AsyncLogWriter {
	h := NewHub()
	go h.Run()
	return &AsyncLogWriter{
		dbURL:         dbURL,
		backend:       detectBackend(dbURL),
		logCh:         make(chan *Entry, 10000),
		batchSize:     1000,
		flushInterval: 500 * time.Millisecond,
		hub:           h,
	}
}

func detectBackend(dbURL string) string {
	u := strings.TrimSpace(dbURL)
	switch {
	case u == "":
		return "none"
	case strings.HasPrefix(u, "sqlite://"), strings.HasPrefix(u, "file:"):
		return "sqlite"
	default:
		return "postgres"
	}
}

func (w *AsyncLogWriter) GetHub() *Hub {
	return w.hub
}

func (w *AsyncLogWriter) ConnectionState() (connected bool, lastError string) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.connected, w.lastError
}

func (w *AsyncLogWriter) setConnectionState(connected bool, lastError string) {
	w.mu.Lock()
	w.connected = connected
	w.lastError = lastError
	w.mu.Unlock()
}

// Start initializes the DB connection and starts the flush loop.
func (w *AsyncLogWriter) Start(ctx context.Context) error {
	if w.dbURL == "" {
		w.setConnectionState(false, "audit persistence disabled (no DATABASE_URL configured)")
		return nil
	}
	if w.backend == "sqlite" {
		path := strings.TrimPrefix(w.dbURL, "sqlite://")
		if path == "" {
			return fmt.Errorf("invalid sqlite url: %s", w.dbURL)
		}
		if strings.HasPrefix(path, "~") {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("resolve home dir: %w", err)
			}
			path = filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("create sqlite parent dir: %w", err)
		}
		db, err := sql.Open("sqlite", path)
		if err != nil {
			return fmt.Errorf("open sqlite: %w", err)
		}
		if _, err := db.ExecContext(ctx, `
			CREATE TABLE IF NOT EXISTS enclave_events (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				session_id TEXT NOT NULL,
				timestamp INTEGER NOT NULL,
				action TEXT NOT NULL,
				status TEXT NOT NULL,
				input TEXT,
				metadata TEXT
			);
			CREATE INDEX IF NOT EXISTS idx_enclave_events_session_ts ON enclave_events(session_id, timestamp DESC);
			CREATE INDEX IF NOT EXISTS idx_enclave_events_ts ON enclave_events(timestamp DESC);
			CREATE INDEX IF NOT EXISTS idx_enclave_events_action ON enclave_events(action);
		`); err != nil {
			_ = db.Close()
			return fmt.Errorf("init sqlite schema: %w", err)
		}
		w.sqlite = db
		w.setConnectionState(true, "")
		log.Info("Connected to sqlite audit store: %s", path)
		w.run(ctx)
		return nil
	}

	config, err := pgxpool.ParseConfig(w.dbURL)
	if err != nil {
		return fmt.Errorf("invalid db url: %w", err)
	}

	// Retry connection with exponential backoff
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			pool, err := pgxpool.NewWithConfig(ctx, config)
			if err == nil {
				if err = pool.Ping(ctx); err == nil {
					w.pool = pool
					w.setConnectionState(true, "")
					log.Info("Connected to database successfully")
					w.run(ctx)
					return nil
				}
			}

			if err != nil {
				w.setConnectionState(false, err.Error())
			}
			log.Error("Database connection failed (backoff %v): %v", backoff, err)

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
	}
}

func (w *AsyncLogWriter) Push(e *Entry) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	if w.hub != nil {
		w.hub.Broadcast(e)
	}
	if w.pool == nil {
		return
	}
	select {
	case w.logCh <- e:
	default:
		// Drop
	}
}

func (w *AsyncLogWriter) run(ctx context.Context) {
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()

	batch := make([]*Entry, 0, w.batchSize)

	flush := func() {
		if len(batch) > 0 {
			if err := w.writeBatch(context.Background(), batch); err != nil {
				log.Error("Failed to write batch: %v", err)
			}
			batch = batch[:0]
		}
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			if w.pool != nil {
				w.pool.Close()
			}
			if w.sqlite != nil {
				_ = w.sqlite.Close()
			}
			return
		case e := <-w.logCh:
			batch = append(batch, e)
			if len(batch) >= w.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (w *AsyncLogWriter) writeBatch(ctx context.Context, entries []*Entry) error {
	if w.backend == "sqlite" {
		tx, err := w.sqlite.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO enclave_events(session_id, timestamp, action, status, input, metadata) VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		defer stmt.Close()
		for _, e := range entries {
			meta, _ := json.Marshal(e.Metadata)
			if _, err := stmt.ExecContext(ctx,
				sanitize(e.SessionID),
				e.Timestamp.UnixNano(),
				sanitize(e.Action),
				sanitize(e.Status),
				sanitize(e.Input),
				sanitize(string(meta)),
			); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
		return tx.Commit()
	}
	rows := make([][]interface{}, len(entries))
	for i, e := range entries {
		meta, _ := json.Marshal(e.Metadata)

		rows[i] = []interface{}{
			sanitize(e.SessionID),
			e.Timestamp.UnixNano(), // DB expects int64
			sanitize(e.Action),
			sanitize(e.Status),
			sanitize(e.Input),
			sanitize(string(meta)),
		}
	}

	_, err := w.pool.CopyFrom(
		ctx,
		pgx.Identifier{"enclave_events"},
		[]string{"session_id", "timestamp", "action", "status", "input", "metadata"},
		pgx.CopyFromRows(rows),
	)
	return err
}

func sanitize(s string) string {
	// Remove null bytes which cause PostgreSQL UTF-8 errors
	return string(bytes.ReplaceAll([]byte(s), []byte{0x00}, []byte{}))
}

// Summary holds aggregated audit stats.
type Summary struct {
	TotalEvents int64 `json:"total"`
	Blocked     int64 `json:"blocked"`
	Errors      int64 `json:"errors"`
	Network     int64 `json:"network"`
	FileSystem  int64 `json:"filesystem"`
	Execution   int64 `json:"execution"`
}

type PolicyIntentOverallSummary struct {
	Runs               int64   `json:"runs"`
	Errors             int64   `json:"errors"`
	AvgLatencyMS       float64 `json:"avg_latency_ms"`
	AvgConfidence      float64 `json:"avg_confidence"`
	StrictBlockedCount int64   `json:"strict_blocked_count"`
}

type PolicyIntentModelSummary struct {
	Provider           string  `json:"provider"`
	Model              string  `json:"model"`
	Runs               int64   `json:"runs"`
	Errors             int64   `json:"errors"`
	AvgLatencyMS       float64 `json:"avg_latency_ms"`
	AvgConfidence      float64 `json:"avg_confidence"`
	StrictBlockedCount int64   `json:"strict_blocked_count"`
}

type PolicyIntentSummary struct {
	Overall PolicyIntentOverallSummary `json:"overall"`
	ByModel []PolicyIntentModelSummary `json:"by_model"`
}

func (w *AsyncLogWriter) GetLogs(ctx context.Context, sessionID string, limit int) ([]*Entry, error) {
	if w.pool == nil && w.sqlite == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	// Use explicit columns to match Scan
	query := `
		SELECT session_id, timestamp, action, status, input, metadata
		FROM enclave_events
		WHERE ($1 = '' OR session_id = $1::uuid)
		ORDER BY timestamp DESC
		LIMIT $2
	`
	// Note: session_id in DB is UUID, but input is string. Cast it.
	// If input is empty string, it might fail cast if we aren't careful.
	// The WHERE clause ($1 = '' OR session_id = $1::uuid) handles empty string case IF $1 is text.
	// But binding $1 as string to UUID column might fail.
	// Let's adjust query to be safe: WHERE ($1 = '' OR session_id::text = $1)

	query = `
		SELECT session_id, timestamp, action, status, input, metadata
		FROM enclave_events
		WHERE ($1 = '' OR session_id::text = $1)
		ORDER BY timestamp DESC
		LIMIT $2
	`

	var result []*Entry
	if w.backend == "sqlite" {
		query := `
			SELECT session_id, timestamp, action, status, input, metadata
			FROM enclave_events
			WHERE (? = '' OR session_id = ?)
			ORDER BY timestamp DESC
			LIMIT ?
		`
		rows, err := w.sqlite.QueryContext(ctx, query, sessionID, sessionID, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var ts int64
			var runID, action, status, input, metaRaw string
			if err := rows.Scan(&runID, &ts, &action, &status, &input, &metaRaw); err != nil {
				return nil, err
			}
			var meta map[string]interface{}
			_ = json.Unmarshal([]byte(metaRaw), &meta)
			result = append(result, &Entry{
				SessionID: runID,
				Timestamp: time.Unix(0, ts),
				Action:    action,
				Status:    status,
				Input:     input,
				Metadata:  meta,
			})
		}
		return result, nil
	}

	rows, err := w.pool.Query(ctx, query, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var ts int64
		var runID, action, status, input string
		var metaJSON []byte
		if err := rows.Scan(&runID, &ts, &action, &status, &input, &metaJSON); err != nil {
			return nil, err
		}
		var meta map[string]interface{}
		_ = json.Unmarshal(metaJSON, &meta)
		result = append(result, &Entry{
			SessionID: runID,
			Timestamp: time.Unix(0, ts),
			Action:    action,
			Status:    status,
			Input:     input,
			Metadata:  meta,
		})
	}
	return result, nil
}

// GetSummary returns aggregated stats for a session (or all if empty).
func (w *AsyncLogWriter) GetSummary(ctx context.Context, sessionID string) (*Summary, error) {
	if w.pool == nil && w.sqlite == nil {
		return &Summary{}, nil
	}
	if w.backend == "sqlite" {
		query := `
			SELECT
				COUNT(*) as total,
				SUM(CASE WHEN status = 'BLOCKED' THEN 1 ELSE 0 END) as blocked,
				SUM(CASE WHEN status = 'ERROR' THEN 1 ELSE 0 END) as errors,
				SUM(CASE WHEN action LIKE '%NETWORK%' OR action LIKE '%CONNECT%' THEN 1 ELSE 0 END) as network,
				SUM(CASE WHEN action LIKE '%FILE%' OR action LIKE '%open%' THEN 1 ELSE 0 END) as fs,
				SUM(CASE WHEN action LIKE '%EXECUTE%' OR action LIKE '%execve%' THEN 1 ELSE 0 END) as exec
			FROM enclave_events
			WHERE (? = '' OR session_id = ?)
		`
		var s Summary
		if err := w.sqlite.QueryRowContext(ctx, query, sessionID, sessionID).Scan(
			&s.TotalEvents,
			&s.Blocked,
			&s.Errors,
			&s.Network,
			&s.FileSystem,
			&s.Execution,
		); err != nil {
			return nil, err
		}
		return &s, nil
	}

	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'BLOCKED') as blocked,
			COUNT(*) FILTER (WHERE status = 'ERROR') as errors,
			COUNT(*) FILTER (WHERE action LIKE '%NETWORK%' OR action LIKE '%CONNECT%') as network,
			COUNT(*) FILTER (WHERE action LIKE '%FILE%' OR action LIKE '%open%') as fs,
			COUNT(*) FILTER (WHERE action LIKE '%EXECUTE%' OR action LIKE '%execve%') as exec
		FROM enclave_events
		WHERE ($1 = '' OR session_id::text = $1)
	`

	var s Summary
	err := w.pool.QueryRow(ctx, query, sessionID).Scan(
		&s.TotalEvents,
		&s.Blocked,
		&s.Errors,
		&s.Network,
		&s.FileSystem,
		&s.Execution,
	)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (w *AsyncLogWriter) GetPolicyIntentSummary(ctx context.Context, sessionID string) (*PolicyIntentSummary, error) {
	if w.pool == nil && w.sqlite == nil {
		return &PolicyIntentSummary{}, nil
	}
	if w.backend == "sqlite" {
		return &PolicyIntentSummary{}, nil
	}

	query := `
		SELECT
			COALESCE(NULLIF(metadata->>'provider', ''), 'unknown') AS provider,
			COALESCE(NULLIF(metadata->>'model', ''), 'default') AS model,
			COUNT(*) FILTER (WHERE action = 'POLICY:INTENT_EXTRACTED') AS runs,
			COUNT(*) FILTER (WHERE status = 'ERROR') AS errors,
			AVG(CASE
				WHEN (metadata->>'latency_ms') ~ '^[0-9]+(\\.[0-9]+)?$' THEN (metadata->>'latency_ms')::double precision
				ELSE NULL
			END) AS avg_latency_ms,
			AVG(CASE
				WHEN (metadata->>'confidence') ~ '^[0-9]+(\\.[0-9]+)?$' THEN (metadata->>'confidence')::double precision
				ELSE NULL
			END) AS avg_confidence,
			COUNT(*) FILTER (WHERE metadata->>'strict_blocked' = 'true') AS strict_blocked_count
		FROM enclave_events
		WHERE ($1 = '' OR session_id::text = $1)
		  AND action IN ('POLICY:INTENT_EXTRACTED', 'POLICY:OPA_VERDICT', 'POLICY:ENFORCEMENT_APPLIED', 'POLICY:ENFORCEMENT_FAILED')
		GROUP BY provider, model
		ORDER BY runs DESC, errors DESC, provider ASC, model ASC
	`

	rows, err := w.pool.Query(ctx, query, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := &PolicyIntentSummary{}
	var (
		latencyWeightedSum    float64
		latencyWeightedCount  float64
		confidenceWeightedSum float64
		confidenceSampleCount float64
	)

	for rows.Next() {
		var item PolicyIntentModelSummary
		var avgLatency, avgConfidence *float64

		if err := rows.Scan(
			&item.Provider,
			&item.Model,
			&item.Runs,
			&item.Errors,
			&avgLatency,
			&avgConfidence,
			&item.StrictBlockedCount,
		); err != nil {
			return nil, err
		}

		if avgLatency != nil {
			item.AvgLatencyMS = *avgLatency
			latencyWeightedSum += *avgLatency * float64(item.Runs)
			latencyWeightedCount += float64(item.Runs)
		}
		if avgConfidence != nil {
			item.AvgConfidence = *avgConfidence
			confidenceWeightedSum += *avgConfidence * float64(item.Runs)
			confidenceSampleCount += float64(item.Runs)
		}

		result.Overall.Runs += item.Runs
		result.Overall.Errors += item.Errors
		result.Overall.StrictBlockedCount += item.StrictBlockedCount
		result.ByModel = append(result.ByModel, item)
	}

	if latencyWeightedCount > 0 {
		result.Overall.AvgLatencyMS = latencyWeightedSum / latencyWeightedCount
	}
	if confidenceSampleCount > 0 {
		result.Overall.AvgConfidence = confidenceWeightedSum / confidenceSampleCount
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return result, nil
}
