// Package report renders the results as text or as a self-contained HTML page.
package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"math"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/vynak/detection-lab/internal/model"
)

//go:embed template.html
var templates embed.FS

type ruleView struct {
	model.RuleStat
	BarPct int
}

type alertView struct {
	TS        string
	Severity  string
	RuleID    string
	Title     string
	Host      string
	Image     string
	Detail    string
	Malicious bool
}

type page struct {
	Generated    string
	M            model.Metrics
	PrecisionPct int
	RecallPct    int
	Rules        []ruleView
	Alerts       []alertView
}

// WriteText prints a summary that fits in a terminal.
func WriteText(w io.Writer, m model.Metrics, alerts []model.Alert) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintf(tw, "detection-lab\n")
	fmt.Fprintf(tw, "events\t%d (%d malicious, %d benign, %d unlabeled)\n", m.Events, m.Malicious, m.Benign, m.Unlabeled)
	fmt.Fprintf(tw, "alerts\t%d\n", m.Alerts)
	fmt.Fprintf(tw, "precision\t%.1f%% (%d TP / %d FP)\n", m.Precision*100, m.TP, m.FP)
	fmt.Fprintf(tw, "recall\t%.1f%% (%d TP / %d FN)\n", m.Recall*100, m.TP, m.FN)
	if err := tw.Flush(); err != nil {
		return err
	}

	rules := append([]model.RuleStat(nil), m.ByRule...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })

	if len(rules) > 0 {
		fmt.Fprintf(w, "\nby rule\n")
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, r := range rules {
			fmt.Fprintf(tw, "  %s\t%s\t%d alerts\t%d TP\t%d FP\n", r.RuleID, r.Title, r.Alerts, r.TP, r.FP)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if len(alerts) > 0 {
		fmt.Fprintf(w, "\nalerts\n")
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, a := range alerts {
			fmt.Fprintf(tw, "  %s\t%-8s\t%s\t%s\n",
				a.TS.UTC().Format("15:04:05"), a.Severity, a.RuleID, a.Title)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// WriteHTML renders the same data as a single page with no external assets.
func WriteHTML(w io.Writer, m model.Metrics, alerts []model.Alert) error {
	tmpl, err := template.ParseFS(templates, "template.html")
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	maxAlerts := 1
	for _, r := range m.ByRule {
		if r.Alerts > maxAlerts {
			maxAlerts = r.Alerts
		}
	}

	rules := append([]model.RuleStat(nil), m.ByRule...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })
	views := make([]ruleView, 0, len(rules))
	for _, r := range rules {
		views = append(views, ruleView{RuleStat: r, BarPct: r.Alerts * 100 / maxAlerts})
	}

	alertViews := make([]alertView, 0, len(alerts))
	for _, a := range alerts {
		alertViews = append(alertViews, alertView{
			TS:        a.TS.UTC().Format("2006-01-02 15:04:05"),
			Severity:  a.Severity,
			RuleID:    a.RuleID,
			Title:     a.Title,
			Host:      a.Host,
			Image:     a.Image,
			Detail:    a.Detail,
			Malicious: a.Label == "malicious",
		})
	}

	data := page{
		Generated:    time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		M:            m,
		PrecisionPct: int(math.Round(m.Precision * 100)),
		RecallPct:    int(math.Round(m.Recall * 100)),
		Rules:        views,
		Alerts:       alertViews,
	}
	return tmpl.Execute(w, data)
}
