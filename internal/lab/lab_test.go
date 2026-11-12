package lab_test

import (
	"path/filepath"
	"testing"

	"github.com/vynak/detection-lab/internal/lab"
	"github.com/vynak/detection-lab/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "lab.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// TestExampleDataset is the regression fixture for the whole pipeline: the
// numbers in examples/README.md are asserted here.
func TestExampleDataset(t *testing.T) {
	st := newStore(t)

	stats, err := lab.Ingest(st, []string{filepath.Join("..", "..", "examples", "data")}, nil)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if stats.Events != 25 {
		t.Fatalf("ingested %d events, want 25", stats.Events)
	}
	if stats.Warnings != 0 {
		t.Errorf("got %d warnings, want 0", stats.Warnings)
	}

	if _, _, err := lab.Detect(st); err != nil {
		t.Fatalf("detect: %v", err)
	}

	metrics, err := st.Metrics()
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}

	checks := []struct {
		name string
		got  int
		want int
	}{
		{"events", metrics.Events, 25},
		{"malicious", metrics.Malicious, 6},
		{"benign", metrics.Benign, 19},
		{"alerts", metrics.Alerts, 8},
		{"tp", metrics.TP, 6},
		{"fp", metrics.FP, 2},
		{"fn", metrics.FN, 0},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %d, want %d", check.name, check.got, check.want)
		}
	}

	if metrics.Precision < 0.749 || metrics.Precision > 0.751 {
		t.Errorf("precision = %v, want 0.75", metrics.Precision)
	}
	if metrics.Recall != 1 {
		t.Errorf("recall = %v, want 1", metrics.Recall)
	}
}

func TestPerRuleCounts(t *testing.T) {
	st := newStore(t)
	if _, err := lab.Ingest(st, []string{filepath.Join("..", "..", "examples", "data")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lab.Detect(st); err != nil {
		t.Fatal(err)
	}
	metrics, err := st.Metrics()
	if err != nil {
		t.Fatal(err)
	}

	want := map[string][3]int{
		"LAB-001": {2, 1, 1},
		"LAB-002": {1, 1, 0},
		"LAB-003": {1, 1, 0},
		"LAB-004": {2, 1, 1},
		"LAB-005": {1, 1, 0},
		"LAB-006": {1, 1, 0},
	}
	for _, rule := range metrics.ByRule {
		expected, ok := want[rule.RuleID]
		if !ok {
			t.Errorf("unexpected rule %s", rule.RuleID)
			continue
		}
		got := [3]int{rule.Alerts, rule.TP, rule.FP}
		if got != expected {
			t.Errorf("%s: alerts/TP/FP = %v, want %v", rule.RuleID, got, expected)
		}
	}
	if len(metrics.ByRule) != len(want) {
		t.Errorf("got %d rules with alerts, want %d", len(metrics.ByRule), len(want))
	}
}

func TestDetectIsIdempotent(t *testing.T) {
	st := newStore(t)
	if _, err := lab.Ingest(st, []string{filepath.Join("..", "..", "examples", "data")}, nil); err != nil {
		t.Fatal(err)
	}
	if _, first, err := lab.Detect(st); err != nil || first != 8 {
		t.Fatalf("first detect: alerts=%d err=%v", first, err)
	}
	if _, second, err := lab.Detect(st); err != nil || second != 8 {
		t.Fatalf("second detect: alerts=%d err=%v", second, err)
	}

	alerts, err := st.Alerts()
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 8 {
		t.Errorf("stored %d alerts after two runs, want 8", len(alerts))
	}
}
