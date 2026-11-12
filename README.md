# detection-lab

A small detection pipeline: read telemetry, store it in SQLite, run rules, and report how good those rules actually are.

Writing an alert is easy. Knowing whether it is worth an analyst's time needs two things most side projects skip: a dataset with ground truth, and a number. This repo has both.


<img width="1200" height="1300" alt="image" src="https://github.com/user-attachments/assets/d95a9f19-d119-4ffe-b7ec-8bcf3bc752e1" />



```
JSON Lines ──► SQLite ──► 6 rules ──► alerts ──► precision / recall
```

## Quick start

```bash
go run ./cmd/detection-lab run -db lab.db -html report.html examples/data
```

No database to install, no Python, no CGO: SQLite is compiled into the binary.

To get a binary, `go build -o bin/ ./cmd/detection-lab` writes `bin/detection-lab` on Linux and `bin/detection-lab.exe` on Windows.

> Flags go **before** the paths. Go's standard flag parser stops at the first argument, and the CLI tells you when you get it wrong.

Output:

```
ingested 25 event(s) from 1 file(s), 0 warning(s)
produced 8 alert(s)

detection-lab
events     25 (6 malicious, 19 benign, 0 unlabeled)
alerts     8
precision  75.0% (6 TP / 2 FP)
recall     100.0% (6 TP / 0 FN)

by rule
  LAB-001  PowerShell with an encoded command            2 alerts  1 TP  1 FP
  LAB-002  Office application spawned a shell            1 alerts  1 TP  0 FP
  ...
```

`-html report.html` writes a single-page report with the same numbers, no external assets.

## The example dataset

[`examples/`](examples/README.md) contains a synthetic day on one workstation: a phishing document, an encoded PowerShell, a `certutil` download, LSASS access, a vulnerable driver, and shadow copies deleted. Around it, normal noise and **two deliberate false positives** so the metrics mean something.

| Metric | Value |
|---|---|
| Events | 25 (6 malicious, 19 benign) |
| Alerts | 8 |
| True positives | 6 |
| False positives | 2 |
| False negatives | 0 |
| Precision | 75% |
| Recall | 100% |

The end-to-end test asserts exactly these numbers. Change a rule and it tells you what it cost.

## Rules

| Rule | What it catches | Severity | ATT&CK |
|---|---|---|---|
| LAB-001 | PowerShell with `-enc` / `-EncodedCommand` | high | T1059.001 |
| LAB-002 | Office application spawning a shell | high | T1566.001 |
| LAB-003 | Non-system process reading LSASS | critical | T1003.001 |
| LAB-004 | Unsigned driver, or driver from a user-writable path | high | T1068 |
| LAB-005 | `vssadmin` / `wmic` deleting shadow copies | high | T1490 |
| LAB-006 | `certutil` used to download a file | medium | T1105 |

Every rule is a function over a normalized event; none of them knows about SQL or HTTP. That is what keeps the tests short.

## Event schema

One JSON object per line. Unknown fields are ignored, so an exporter can add its own metadata.

```json
{"ts":"2026-11-12T09:04:00Z","event_id":1,"host":"WS-0142","image":"C:\\Windows\\System32\\cmd.exe","parent_image":"C:\\Windows\\explorer.exe","command_line":"cmd.exe /c whoami","user":"CORP\\a.gomez","label":"malicious"}
```

| Field | Notes |
|---|---|
| `ts` | RFC 3339, required |
| `event_id` | Windows/Sysmon id. `1` process start, `3` network, `6` driver load, `10` process access, `4624`/`4625` logon |
| `host` | required |
| `kind` | optional; derived from `event_id` when absent |
| `image`, `parent_image`, `command_line`, `user` | process context |
| `target` | LSASS path for `process_access`, loaded image for `driver_load` |
| `dest_ip`, `dest_port` | network context |
| `signed`, `signature_status` | driver signature |
| `label` | `malicious` or `benign`; without it the event still counts but not in the metrics |

## How the numbers are computed

- **TP**: an alert on an event labeled malicious.
- **FP**: an alert on an event labeled benign.
- **FN**: a malicious event with no alert.
- **Precision** = TP / (TP + FP): of everything we escalated, how much was real.
- **Recall** = TP / (TP + FN): of everything malicious, how much we caught.

One event can produce two alerts; precision counts alerts, recall counts events. That asymmetry is deliberate and worth explaining out loud.

## Commands

| Command | What it does |
|---|---|
| `ingest` | read JSON Lines files (or a directory) into the database |
| `detect` | run the rules over everything stored |
| `report` | print metrics; `-html file` writes the page |
| `run` | ingest + detect + report |

`-db` picks the database (default `lab.db`). Ingest is idempotent: the same file twice does not duplicate rows. Detect replaces the alert set, so running it twice gives the same result.

## Design notes

- **One binary.** SQLite comes from `modernc.org/sqlite`, a pure Go implementation. No CGO means `go build` works on a fresh Windows or Linux machine with nothing installed.
- **The rules are data, not SQL.** They receive a `model.Event` and return a detail string; storage and presentation are somebody else's problem.
- **The dataset is a test fixture.** The numbers in the README are assertions in `internal/lab/lab_test.go`, so documentation cannot drift from behaviour.

## Limits

- The dataset is synthetic. It is a lab, not a capture; it shows the method, not the threat landscape.
- No collection: it reads an export, it does not talk to Sysmon or a SIEM.
- Six rules, Windows-flavoured. Adding more is the point of the design, not a feature of v0.1.
- Metrics need labels. Unlabeled events count as events and never as TP/FP/FN.

## Tests

```bash
go test ./...
go vet ./...
gofmt -l .
```

CI runs the three on every push.

## Layout

```
cmd/detection-lab/   CLI
internal/ingest/     JSON Lines parsing and normalization
internal/rules/      the six rules
internal/store/      SQLite schema, inserts, metrics
internal/report/     text and HTML output
internal/lab/        ingest + detect wiring, used by the CLI and the tests
examples/            the synthetic dataset and its documented results
```

## License

MIT. See [LICENSE](LICENSE).
