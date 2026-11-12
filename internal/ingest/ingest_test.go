package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDerivesKindFromEventID(t *testing.T) {
	line := `{"ts":"2026-11-12T09:03:11Z","event_id":1,"host":"WS-1","image":"C:\\Windows\\System32\\cmd.exe"}`
	events, warnings := Parse(strings.NewReader(line), "")

	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Kind != "process_start" {
		t.Errorf("kind = %q, want process_start", events[0].Kind)
	}
	if events[0].Source != "sysmon" {
		t.Errorf("source = %q, want the sysmon default", events[0].Source)
	}
}

func TestParseKeepsExplicitKindAndSource(t *testing.T) {
	line := `{"ts":"2026-11-12T09:03:11Z","event_id":9999,"kind":"process_start","source":"custom","host":"WS-1"}`
	events, warnings := Parse(strings.NewReader(line), "")

	if len(warnings) != 0 || len(events) != 1 {
		t.Fatalf("events=%d warnings=%v", len(events), warnings)
	}
	if events[0].Source != "custom" {
		t.Errorf("source = %q, want custom", events[0].Source)
	}
}

func TestParseReportsBadLinesWithoutStopping(t *testing.T) {
	lines := strings.Join([]string{
		`{"ts":"2026-11-12T09:00:00Z","event_id":1,"host":"WS-1"}`,
		`not json`,
		`{"ts":"yesterday","event_id":1,"host":"WS-1"}`,
		`{"ts":"2026-11-12T09:10:00Z","event_id":1,"host":"WS-1"}`,
	}, "\n")

	events, warnings := Parse(strings.NewReader(lines), "")

	if len(events) != 2 {
		t.Errorf("got %d valid events, want 2", len(events))
	}
	if len(warnings) != 2 {
		t.Errorf("got %d warnings, want 2", len(warnings))
	}
}

func TestParseRejectsUnknownEventIDWithoutKind(t *testing.T) {
	line := `{"ts":"2026-11-12T09:00:00Z","event_id":7,"host":"WS-1"}`

	events, warnings := Parse(strings.NewReader(line), "")

	if len(events) != 0 || len(warnings) != 1 {
		t.Fatalf("events=%d warnings=%v", len(events), warnings)
	}
}

func TestParseRejectsUnknownLabel(t *testing.T) {
	line := `{"ts":"2026-11-12T09:00:00Z","event_id":1,"host":"WS-1","label":"maybe"}`

	_, warnings := Parse(strings.NewReader(line), "")

	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want one", warnings)
	}
}

func TestFilesWalksDirectories(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(dir, "a.jsonl"),
		filepath.Join(nested, "b.jsonl"),
		filepath.Join(dir, "ignored.txt"),
	} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	files, err := Files([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Errorf("got %d files, want 2: %v", len(files), files)
	}
}
