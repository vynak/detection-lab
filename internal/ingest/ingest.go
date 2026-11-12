// Package ingest reads JSON Lines telemetry and normalizes it.
package ingest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vynak/detection-lab/internal/model"
)

// rawEvent mirrors the JSON Lines schema documented in the README. Unknown
// fields are ignored, so an exporter can add its own metadata.
type rawEvent struct {
	TS          string `json:"ts"`
	Source      string `json:"source"`
	EventID     int    `json:"event_id"`
	Host        string `json:"host"`
	Kind        string `json:"kind"`
	Image       string `json:"image"`
	ParentImage string `json:"parent_image"`
	CommandLine string `json:"command_line"`
	User        string `json:"user"`
	Target      string `json:"target"`
	DestIP      string `json:"dest_ip"`
	DestPort    int    `json:"dest_port"`
	Signed      *bool  `json:"signed"`
	SigStatus   string `json:"signature_status"`
	Label       string `json:"label"`
}

// KindFromEventID maps a Windows/Sysmon event id to the normalized kind.
func KindFromEventID(eventID int) string {
	switch eventID {
	case 1, 4688:
		return "process_start"
	case 3:
		return "network_connect"
	case 6:
		return "driver_load"
	case 10:
		return "process_access"
	case 4624, 4625:
		return "logon"
	default:
		return ""
	}
}

func normalize(raw rawEvent, source string, line int) (model.Event, error) {
	if strings.TrimSpace(raw.TS) == "" {
		return model.Event{}, fmt.Errorf("line %d: missing ts", line)
	}
	ts, err := time.Parse(time.RFC3339, raw.TS)
	if err != nil {
		return model.Event{}, fmt.Errorf("line %d: bad ts %q", line, raw.TS)
	}
	if raw.Host == "" {
		return model.Event{}, fmt.Errorf("line %d: missing host", line)
	}
	if raw.EventID == 0 {
		return model.Event{}, fmt.Errorf("line %d: missing event_id", line)
	}
	kind := raw.Kind
	if kind == "" {
		kind = KindFromEventID(raw.EventID)
	}
	if kind == "" {
		return model.Event{}, fmt.Errorf("line %d: unknown event_id %d and no kind", line, raw.EventID)
	}
	if raw.Source == "" {
		raw.Source = source
	}
	if raw.Source == "" {
		raw.Source = "sysmon"
	}
	if raw.Label != "" && raw.Label != "malicious" && raw.Label != "benign" {
		return model.Event{}, fmt.Errorf("line %d: label must be malicious or benign, got %q", line, raw.Label)
	}

	return model.Event{
		TS:          ts.UTC(),
		Source:      raw.Source,
		EventID:     raw.EventID,
		Host:        raw.Host,
		Kind:        kind,
		Image:       raw.Image,
		ParentImage: raw.ParentImage,
		CommandLine: raw.CommandLine,
		User:        raw.User,
		Target:      raw.Target,
		DestIP:      raw.DestIP,
		DestPort:    raw.DestPort,
		Signed:      raw.Signed,
		SigStatus:   raw.SigStatus,
		Label:       raw.Label,
	}, nil
}

// Parse reads JSON Lines from r. Bad lines are returned as warnings instead of
// aborting the whole file: one corrupt line should not hide the other 10k.
func Parse(r io.Reader, source string) ([]model.Event, []error) {
	var events []model.Event
	var warnings []error

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var raw rawEvent
		if err := json.Unmarshal([]byte(text), &raw); err != nil {
			warnings = append(warnings, fmt.Errorf("line %d: invalid JSON: %w", line, err))
			continue
		}
		event, err := normalize(raw, source, line)
		if err != nil {
			warnings = append(warnings, err)
			continue
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		warnings = append(warnings, fmt.Errorf("read: %w", err))
	}
	return events, warnings
}

// Files expands the arguments: a directory is walked for *.jsonl files.
func Files(paths []string) ([]string, error) {
	var files []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files = append(files, path)
			continue
		}
		err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.EqualFold(filepath.Ext(p), ".jsonl") {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}
