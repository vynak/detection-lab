// Package model holds the shared types of the lab.
package model

import "time"

// Event is one normalized telemetry record. Every source is mapped into this
// shape before it reaches SQLite, so rules never parse a log twice.
type Event struct {
	ID          int64
	TS          time.Time
	Source      string // sysmon, security
	EventID     int
	Host        string
	Kind        string // process_start, network_connect, driver_load, process_access, logon
	Image       string
	ParentImage string
	CommandLine string
	User        string
	Target      string
	DestIP      string
	DestPort    int
	Signed      *bool
	SigStatus   string
	Label       string // malicious, benign, empty when unlabeled
	Raw         string
}

// Alert is a rule match against one event.
type Alert struct {
	ID        int64
	RuleID    string
	Title     string
	Severity  string
	Technique string
	EventID   int64
	TS        time.Time
	Host      string
	Image     string
	Detail    string
	Label     string
}

// RuleStat is the per-rule breakdown used by the report.
type RuleStat struct {
	RuleID   string
	Title    string
	Severity string
	Alerts   int
	TP       int
	FP       int
}

// Metrics is everything the report needs, computed once.
type Metrics struct {
	Events     int
	Malicious  int
	Benign     int
	Unlabeled  int
	Alerts     int
	TP         int
	FP         int
	FN         int
	Precision  float64
	Recall     float64
	ByRule     []RuleStat
	BySeverity map[string]int
}

// PrecisionOrZero avoids NaN in the report when there are no alerts.
func PrecisionOrZero(tp, fp int) float64 {
	if tp+fp == 0 {
		return 0
	}
	return float64(tp) / float64(tp+fp)
}

// RecallOrZero avoids NaN when the dataset has no malicious events.
func RecallOrZero(tp, fn int) float64 {
	if tp+fn == 0 {
		return 0
	}
	return float64(tp) / float64(tp+fn)
}
