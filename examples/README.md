# Example dataset

A synthetic day on `WS-0142`, a finance workstation. It is a lab, not a
capture: the timestamps and hosts are invented, but the events follow a real
phishing-to-ransomware pattern so the rules have something honest to chew on.

## The story

1. **09:03** — `WINWORD.EXE` spawns `cmd.exe`. A malicious document runs a command.
2. **09:04** — `cmd.exe` starts PowerShell with `-enc`. The encoded blob downloads the next stage.
3. **09:20** — `certutil -urlcache` pulls a binary from `185.220.101.7`.
4. **09:41** — `procdump64.exe` opens `lsass.exe` with a full-access mask. Credential dumping.
5. **10:05** — an unsigned driver loads from `%TEMP%`. Classic BYOVD.
6. **10:22** — `vssadmin delete shadows`. Recovery is disabled before encryption.

Around it, normal noise: Outlook, Chrome, Teams, an inventory script, a driver
update, a developer opening VS Code.

## The two deliberate false positives

A dataset where every rule is perfect teaches nothing, so two benign events are
there to be caught:

- **09:05** — an IT admin running `powershell -EncodedCommand`. LAB-001 fires.
- **13:22** — a legitimate vendor driver installed under `C:\ProgramData`. LAB-004 fires.

They are the price of those rules, and the report shows it.

## Expected result

| Metric | Value |
|---|---|
| Events | 25 (6 malicious, 19 benign) |
| Alerts | 8 |
| True positives | 6 |
| False positives | 2 |
| False negatives | 0 |
| Precision | 75% |
| Recall | 100% |

Per rule: LAB-001 → 2 alerts (1 TP, 1 FP), LAB-002 → 1 TP, LAB-003 → 1 TP,
LAB-004 → 2 alerts (1 TP, 1 FP), LAB-005 → 1 TP, LAB-006 → 1 TP.

## Run it

```bash
detection-lab run examples/data --html report.html
```

`tests/e2e_test.go` asserts exactly these numbers, so the dataset doubles as a
regression fixture: if a rule changes, the test tells you what it cost.
