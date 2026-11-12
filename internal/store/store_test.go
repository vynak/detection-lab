package store_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vynak/detection-lab/internal/model"
	"github.com/vynak/detection-lab/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func event(ts string, label string) model.Event {
	return model.Event{
		TS:      mustTime(ts),
		Source:  "sysmon",
		EventID: 1,
		Host:    "WS-1",
		Kind:    "process_start",
		Image:   `C:\Windows\System32\cmd.exe`,
		Label:   label,
	}
}

func mustTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return parsed
}

func TestInsertEventIsIdempotent(t *testing.T) {
	st := newStore(t)
	first, err := st.InsertEvent(event("2026-11-12T09:00:00Z", "benign"))
	if err != nil {
		t.Fatal(err)
	}
	if first == 0 {
		t.Fatal("expected a new row id")
	}

	if _, err := st.InsertEvent(event("2026-11-12T09:00:00Z", "benign")); err != nil {
		t.Fatal(err)
	}

	events, err := st.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Errorf("got %d events after a duplicate insert, want 1", len(events))
	}
}

func TestMetricsCountTPFPAndFN(t *testing.T) {
	st := newStore(t)
	maliciousHit, _ := st.InsertEvent(event("2026-11-12T09:00:00Z", "malicious"))
	maliciousMissed, _ := st.InsertEvent(event("2026-11-12T09:01:00Z", "malicious"))
	benignHit, _ := st.InsertEvent(event("2026-11-12T09:02:00Z", "benign"))

	err := st.ReplaceAlerts([]model.Alert{
		{RuleID: "LAB-001", Title: "t", Severity: "high", Technique: "T1", EventID: maliciousHit},
		{RuleID: "LAB-002", Title: "t", Severity: "high", Technique: "T1", EventID: benignHit},
	})
	if err != nil {
		t.Fatal(err)
	}

	metrics, err := st.Metrics()
	if err != nil {
		t.Fatal(err)
	}

	if metrics.Events != 3 || metrics.Malicious != 2 || metrics.Benign != 1 {
		t.Errorf("events=%d malicious=%d benign=%d", metrics.Events, metrics.Malicious, metrics.Benign)
	}
	if metrics.Alerts != 2 || metrics.TP != 1 || metrics.FP != 1 || metrics.FN != 1 {
		t.Errorf("alerts=%d TP=%d FP=%d FN=%d", metrics.Alerts, metrics.TP, metrics.FP, metrics.FN)
	}
	if metrics.Precision != 0.5 || metrics.Recall != 0.5 {
		t.Errorf("precision=%v recall=%v, want 0.5 and 0.5", metrics.Precision, metrics.Recall)
	}
	_ = maliciousMissed
}

func TestReplaceAlertsClearsThePreviousRun(t *testing.T) {
	st := newStore(t)
	id, _ := st.InsertEvent(event("2026-11-12T09:00:00Z", "malicious"))

	alert := model.Alert{RuleID: "LAB-001", Title: "t", Severity: "high", Technique: "T1", EventID: id}
	if err := st.ReplaceAlerts([]model.Alert{alert}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceAlerts([]model.Alert{alert}); err != nil {
		t.Fatal(err)
	}

	alerts, err := st.Alerts()
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Errorf("got %d alerts after two runs, want 1", len(alerts))
	}
}
