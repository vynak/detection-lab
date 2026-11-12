// Package rules is the detection content of the lab: small, named functions
// with an ATT&CK mapping. Each one is independent, which keeps the tests short
// and the false-positive discussion honest.
package rules

import (
	"regexp"
	"strings"

	"github.com/vynak/detection-lab/internal/model"
)

// Rule is one detection. Match returns a human detail and whether it fired.
type Rule struct {
	ID        string
	Title     string
	Severity  string
	Technique string
	Match     func(model.Event) (string, bool)
}

var (
	encodedPowerShell = regexp.MustCompile(`(?i)-enc(odedcommand)?\b`)
	shadowCopyDelete  = regexp.MustCompile(`(?i)(vssadmin(\.exe)?\b.*\bdelete\b.*\bshadows?\b)|(wmic(\.exe)?\b.*\bshadowcopy\b.*\bdelete\b)`)
	certutilDownload  = regexp.MustCompile(`(?i)certutil(\.exe)?\b.*-(urlcache|verifyctl)\b`)
)

var shells = map[string]bool{
	"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true,
	"wscript.exe": true, "cscript.exe": true, "mshta.exe": true, "rundll32.exe": true,
}

var officeApps = map[string]bool{
	"winword.exe": true, "excel.exe": true, "powerpnt.exe": true, "outlook.exe": true,
}

var writableDirs = []string{`\users\`, `\temp\`, `\appdata\`, `\programdata\`, `\public\`, `\$recycle.bin\`}

func baseName(path string) string {
	normalized := strings.ReplaceAll(path, "/", `\`)
	if i := strings.LastIndex(normalized, `\`); i >= 0 {
		return strings.ToLower(normalized[i+1:])
	}
	return strings.ToLower(normalized)
}

func isSystemImage(path string) bool {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	return strings.Contains(lower, `\windows\system32\`) || strings.Contains(lower, `\windows\syswow64\`)
}

// All returns the rules in the order they are documented.
func All() []Rule {
	return []Rule{
		{
			ID: "LAB-001", Title: "PowerShell with an encoded command", Severity: "high", Technique: "T1059.001",
			Match: func(e model.Event) (string, bool) {
				if e.Kind != "process_start" || !shells[baseName(e.Image)] {
					return "", false
				}
				if !encodedPowerShell.MatchString(e.CommandLine) {
					return "", false
				}
				return "command line contains -enc/-EncodedCommand", true
			},
		},
		{
			ID: "LAB-002", Title: "Office application spawned a shell", Severity: "high", Technique: "T1566.001",
			Match: func(e model.Event) (string, bool) {
				if e.Kind != "process_start" {
					return "", false
				}
				if !officeApps[baseName(e.ParentImage)] || !shells[baseName(e.Image)] {
					return "", false
				}
				return baseName(e.ParentImage) + " -> " + baseName(e.Image), true
			},
		},
		{
			ID: "LAB-003", Title: "Non-system process accessed LSASS", Severity: "critical", Technique: "T1003.001",
			Match: func(e model.Event) (string, bool) {
				if e.Kind != "process_access" || baseName(e.Target) != "lsass.exe" {
					return "", false
				}
				if isSystemImage(e.Image) {
					return "", false
				}
				return "access from " + e.Image, true
			},
		},
		{
			ID: "LAB-004", Title: "Unsigned driver or loaded from a user-writable path", Severity: "high", Technique: "T1068",
			Match: func(e model.Event) (string, bool) {
				if e.Kind != "driver_load" {
					return "", false
				}
				if e.Signed != nil && !*e.Signed {
					return "driver is not signed", true
				}
				if isSystemImage(e.Image) {
					return "", false
				}
				lower := strings.ToLower(strings.ReplaceAll(e.Image, "/", `\`))
				for _, dir := range writableDirs {
					if strings.Contains(lower, dir) {
						return "loaded from " + e.Image, true
					}
				}
				return "", false
			},
		},
		{
			ID: "LAB-005", Title: "Shadow copies deleted", Severity: "high", Technique: "T1490",
			Match: func(e model.Event) (string, bool) {
				if e.Kind != "process_start" || !shadowCopyDelete.MatchString(e.CommandLine) {
					return "", false
				}
				return "inhibits system recovery", true
			},
		},
		{
			ID: "LAB-006", Title: "certutil used to download a file", Severity: "medium", Technique: "T1105",
			Match: func(e model.Event) (string, bool) {
				if e.Kind != "process_start" || baseName(e.Image) != "certutil.exe" {
					return "", false
				}
				if !certutilDownload.MatchString(e.CommandLine) {
					return "", false
				}
				return "command line uses -urlcache/-verifyctl", true
			},
		},
	}
}

// Evaluate runs every rule against one event and returns the matches.
func Evaluate(e model.Event, all []Rule) []model.Alert {
	var alerts []model.Alert
	for _, rule := range all {
		detail, ok := rule.Match(e)
		if !ok {
			continue
		}
		alerts = append(alerts, model.Alert{
			RuleID:    rule.ID,
			Title:     rule.Title,
			Severity:  rule.Severity,
			Technique: rule.Technique,
			EventID:   e.ID,
			TS:        e.TS,
			Host:      e.Host,
			Image:     e.Image,
			Detail:    detail,
			Label:     e.Label,
		})
	}
	return alerts
}
