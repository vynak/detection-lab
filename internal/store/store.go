// Package store owns the SQLite schema and every query in the lab.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure Go driver: no CGO, builds on Windows and Linux

	"github.com/vynak/detection-lab/internal/model"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	ts           TEXT    NOT NULL,
	source       TEXT    NOT NULL,
	event_id     INTEGER NOT NULL,
	host         TEXT    NOT NULL,
	kind         TEXT    NOT NULL,
	image        TEXT    NOT NULL DEFAULT '',
	parent_image TEXT    NOT NULL DEFAULT '',
	command_line TEXT    NOT NULL DEFAULT '',
	user         TEXT    NOT NULL DEFAULT '',
	target       TEXT    NOT NULL DEFAULT '',
	dest_ip      TEXT    NOT NULL DEFAULT '',
	dest_port    INTEGER NOT NULL DEFAULT 0,
	signed       INTEGER,
	sig_status   TEXT    NOT NULL DEFAULT '',
	label        TEXT    NOT NULL DEFAULT '',
	raw          TEXT    NOT NULL DEFAULT '',
	UNIQUE (ts, host, event_id, image, command_line)
);

CREATE TABLE IF NOT EXISTS alerts (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	rule_id   TEXT    NOT NULL,
	title     TEXT    NOT NULL,
	severity  TEXT    NOT NULL,
	technique TEXT    NOT NULL,
	event_id  INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
	detail    TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_alerts_event ON alerts(event_id);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
`

// Store is a thin wrapper around the database handle.
type Store struct {
	db *sql.DB
}

// Open creates or opens the database and applies the schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the handle.
func (s *Store) Close() error { return s.db.Close() }

// InsertEvent stores one event and returns its id. Re-ingesting the same file
// is safe: the unique key makes the second insert a no-op.
func (s *Store) InsertEvent(e model.Event) (int64, error) {
	var signed any
	if e.Signed != nil {
		if *e.Signed {
			signed = 1
		} else {
			signed = 0
		}
	}

	result, err := s.db.Exec(`
		INSERT OR IGNORE INTO events
			(ts, source, event_id, host, kind, image, parent_image, command_line,
			 user, target, dest_ip, dest_port, signed, sig_status, label, raw)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS.UTC().Format(time.RFC3339Nano), e.Source, e.EventID, e.Host, e.Kind,
		e.Image, e.ParentImage, e.CommandLine, e.User, e.Target, e.DestIP,
		e.DestPort, signed, e.SigStatus, e.Label, e.Raw,
	)
	if err != nil {
		return 0, fmt.Errorf("insert event: %w", err)
	}
	id, _ := result.LastInsertId()
	return id, nil
}

// Events returns every stored event in time order.
func (s *Store) Events() ([]model.Event, error) {
	rows, err := s.db.Query(`
		SELECT id, ts, source, event_id, host, kind, image, parent_image,
		       command_line, user, target, dest_ip, dest_port, signed, sig_status, label
		FROM events ORDER BY ts, id`)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var events []model.Event
	for rows.Next() {
		var (
			e      model.Event
			ts     string
			signed sql.NullInt64
		)
		if err := rows.Scan(&e.ID, &ts, &e.Source, &e.EventID, &e.Host, &e.Kind,
			&e.Image, &e.ParentImage, &e.CommandLine, &e.User, &e.Target,
			&e.DestIP, &e.DestPort, &signed, &e.SigStatus, &e.Label); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		e.TS, _ = time.Parse(time.RFC3339Nano, ts)
		if signed.Valid {
			value := signed.Int64 == 1
			e.Signed = &value
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

// ReplaceAlerts deletes the previous run and stores a new one. Detection is
// deterministic, so re-running it should not duplicate anything.
func (s *Store) ReplaceAlerts(alerts []model.Alert) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM alerts`); err != nil {
		return fmt.Errorf("clear alerts: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT INTO alerts (rule_id, title, severity, technique, event_id, detail)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare alert insert: %w", err)
	}
	defer stmt.Close()

	for _, a := range alerts {
		if _, err := stmt.Exec(a.RuleID, a.Title, a.Severity, a.Technique, a.EventID, a.Detail); err != nil {
			return fmt.Errorf("insert alert: %w", err)
		}
	}
	return tx.Commit()
}

// Alerts returns every alert joined with the event it fired on.
func (s *Store) Alerts() ([]model.Alert, error) {
	rows, err := s.db.Query(`
		SELECT a.id, a.rule_id, a.title, a.severity, a.technique, a.event_id,
		       e.ts, e.host, e.image, a.detail, e.label
		FROM alerts a JOIN events e ON e.id = a.event_id
		ORDER BY e.ts, a.id`)
	if err != nil {
		return nil, fmt.Errorf("query alerts: %w", err)
	}
	defer rows.Close()

	var alerts []model.Alert
	for rows.Next() {
		var (
			a  model.Alert
			ts string
		)
		if err := rows.Scan(&a.ID, &a.RuleID, &a.Title, &a.Severity, &a.Technique,
			&a.EventID, &ts, &a.Host, &a.Image, &a.Detail, &a.Label); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		a.TS, _ = time.Parse(time.RFC3339Nano, ts)
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// Metrics computes precision and recall against the labels stored with the
// events. An event labeled malicious with no alert counts as a false negative.
func (s *Store) Metrics() (model.Metrics, error) {
	events, err := s.Events()
	if err != nil {
		return model.Metrics{}, err
	}
	alerts, err := s.Alerts()
	if err != nil {
		return model.Metrics{}, err
	}

	metrics := model.Metrics{BySeverity: map[string]int{}}
	alerted := map[int64]bool{}
	perRule := map[string]*model.RuleStat{}

	for _, e := range events {
		metrics.Events++
		switch e.Label {
		case "malicious":
			metrics.Malicious++
		case "benign":
			metrics.Benign++
		default:
			metrics.Unlabeled++
		}
	}

	for _, a := range alerts {
		alerted[a.EventID] = true
		metrics.Alerts++
		metrics.BySeverity[a.Severity]++

		stat, ok := perRule[a.RuleID]
		if !ok {
			stat = &model.RuleStat{RuleID: a.RuleID, Title: a.Title, Severity: a.Severity}
			perRule[a.RuleID] = stat
		}
		stat.Alerts++
		if a.Label == "malicious" {
			metrics.TP++
			stat.TP++
		} else if a.Label == "benign" {
			metrics.FP++
			stat.FP++
		}
	}

	for _, e := range events {
		if e.Label == "malicious" && !alerted[e.ID] {
			metrics.FN++
		}
	}

	metrics.Precision = model.PrecisionOrZero(metrics.TP, metrics.FP)
	metrics.Recall = model.RecallOrZero(metrics.TP, metrics.FN)
	for _, stat := range perRule {
		metrics.ByRule = append(metrics.ByRule, *stat)
	}
	return metrics, nil
}
