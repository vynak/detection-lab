// Package lab wires ingest, rules and storage together. The CLI and the tests
// share it, so the end-to-end behaviour has exactly one implementation.
package lab

import (
	"os"

	"github.com/vynak/detection-lab/internal/ingest"
	"github.com/vynak/detection-lab/internal/model"
	"github.com/vynak/detection-lab/internal/rules"
	"github.com/vynak/detection-lab/internal/store"
)

// IngestStats summarizes one ingest run.
type IngestStats struct {
	Events   int
	Warnings int
	Files    int
}

// WarnFunc receives each line that could not be normalized.
type WarnFunc func(path string, err error)

// Ingest reads every JSON Lines file under paths and stores the events.
func Ingest(st *store.Store, paths []string, warn WarnFunc) (IngestStats, error) {
	files, err := ingest.Files(paths)
	if err != nil {
		return IngestStats{}, err
	}

	stats := IngestStats{Files: len(files)}
	for _, path := range files {
		handle, err := os.Open(path)
		if err != nil {
			return stats, err
		}
		events, warnings := ingest.Parse(handle, "")
		handle.Close()

		stats.Warnings += len(warnings)
		if warn != nil {
			for _, warning := range warnings {
				warn(path, warning)
			}
		}
		for _, event := range events {
			if _, err := st.InsertEvent(event); err != nil {
				return stats, err
			}
			stats.Events++
		}
	}
	return stats, nil
}

// Detect runs every rule over the stored events and replaces the alert set.
func Detect(st *store.Store) (events int, alerts int, err error) {
	stored, err := st.Events()
	if err != nil {
		return 0, 0, err
	}

	all := rules.All()
	matches := make([]model.Alert, 0, len(stored))
	for _, event := range stored {
		matches = append(matches, rules.Evaluate(event, all)...)
	}
	if err := st.ReplaceAlerts(matches); err != nil {
		return len(stored), 0, err
	}
	return len(stored), len(matches), nil
}
