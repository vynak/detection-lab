// Command detection-lab ingests telemetry, runs detection rules over it and
// reports precision and recall against the labels in the dataset.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vynak/detection-lab/internal/lab"
	"github.com/vynak/detection-lab/internal/report"
	"github.com/vynak/detection-lab/internal/rules"
	"github.com/vynak/detection-lab/internal/store"
)

const usage = `detection-lab — a small detection pipeline over SQLite

Usage:
  detection-lab <command> [flags] [arguments]

Commands:
  ingest   read JSON Lines files into the database
  detect   run the rules over everything stored
  report   print the metrics, optionally as HTML
  run      ingest + detect + report in one step

Examples:
  detection-lab run examples/data
  detection-lab ingest -db lab.db examples/data/sysmon.jsonl
  detection-lab detect -db lab.db
  detection-lab report -db lab.db -html report.html
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "ingest":
		err = cmdIngest(os.Args[2:])
	case "detect":
		err = cmdDetect(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "detection-lab:", err)
		os.Exit(1)
	}
}

// rejectFlagsAfterPaths turns the Go flag package's silent behaviour into a
// clear error: after the first positional argument, "-db foo" is treated as
// another path, which fails with a confusing "file not found".
func rejectFlagsAfterPaths(fs *flag.FlagSet) error {
	for _, arg := range fs.Args() {
		if strings.HasPrefix(arg, "-") {
			return fmt.Errorf("flag %q must come before the file paths (Go stops parsing flags at the first argument)", arg)
		}
	}
	return nil
}

func openStore(path string) (*store.Store, error) {
	return store.Open(path)
}

func warnToStderr(path string, err error) {
	fmt.Fprintf(os.Stderr, "warning: %s: %v\n", path, err)
}

func printReport(st *store.Store, htmlPath string) error {
	metrics, err := st.Metrics()
	if err != nil {
		return err
	}
	alerts, err := st.Alerts()
	if err != nil {
		return err
	}
	if err := report.WriteText(os.Stdout, metrics, alerts); err != nil {
		return err
	}
	if htmlPath == "" {
		return nil
	}

	file, err := os.Create(htmlPath)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := report.WriteHTML(file, metrics, alerts); err != nil {
		return err
	}
	fmt.Printf("\nhtml report written to %s\n", htmlPath)
	return nil
}

func cmdIngest(args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	db := fs.String("db", "lab.db", "SQLite database file")
	quiet := fs.Bool("quiet", false, "do not print per-line warnings")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("ingest needs a file or a directory")
	}
	if err := rejectFlagsAfterPaths(fs); err != nil {
		return err
	}

	st, err := openStore(*db)
	if err != nil {
		return err
	}
	defer st.Close()

	var warn lab.WarnFunc
	if !*quiet {
		warn = warnToStderr
	}
	stats, err := lab.Ingest(st, fs.Args(), warn)
	if err != nil {
		return err
	}
	fmt.Printf("ingested %d event(s) from %d file(s), %d warning(s)\n",
		stats.Events, stats.Files, stats.Warnings)
	return nil
}

func cmdDetect(args []string) error {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	db := fs.String("db", "lab.db", "SQLite database file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := openStore(*db)
	if err != nil {
		return err
	}
	defer st.Close()

	events, alerts, err := lab.Detect(st)
	if err != nil {
		return err
	}
	fmt.Printf("ran %d rules over %d event(s) and produced %d alert(s)\n",
		len(rules.All()), events, alerts)
	return nil
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	db := fs.String("db", "lab.db", "SQLite database file")
	html := fs.String("html", "", "write a self-contained HTML report to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := openStore(*db)
	if err != nil {
		return err
	}
	defer st.Close()

	return printReport(st, *html)
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	db := fs.String("db", "lab.db", "SQLite database file")
	html := fs.String("html", "", "write a self-contained HTML report to this path")
	quiet := fs.Bool("quiet", false, "do not print per-line warnings")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("run needs at least one file or directory")
	}
	if err := rejectFlagsAfterPaths(fs); err != nil {
		return err
	}

	st, err := openStore(*db)
	if err != nil {
		return err
	}
	defer st.Close()

	var warn lab.WarnFunc
	if !*quiet {
		warn = warnToStderr
	}
	stats, err := lab.Ingest(st, fs.Args(), warn)
	if err != nil {
		return err
	}
	fmt.Printf("ingested %d event(s) from %d file(s), %d warning(s)\n",
		stats.Events, stats.Files, stats.Warnings)

	_, alerts, err := lab.Detect(st)
	if err != nil {
		return err
	}
	fmt.Printf("produced %d alert(s)\n\n", alerts)

	return printReport(st, *html)
}
