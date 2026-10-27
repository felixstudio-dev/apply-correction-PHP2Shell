package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/felixstudio-dev/apply-correction-PHP2Shell/internal/assessment"
	"github.com/felixstudio-dev/apply-correction-PHP2Shell/internal/inventory"
	"github.com/felixstudio-dev/apply-correction-PHP2Shell/internal/mitigation"
)

type Report struct {
	Timestamp     string             `json:"timestamp_utc"`
	HostOS        string             `json:"host_os"`
	Status        string             `json:"status"`
	Note          string             `json:"note"`
	Installations []Installation     `json:"installations"`
	Action        *mitigation.Record `json:"action,omitempty"`
}
type Installation struct {
	inventory.PHP
	Findings []assessment.Finding `json:"findings,omitempty"`
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 && (args[0] == "scan" || args[0] == "verify" || args[0] == "report") {
		args = append([]string{"--" + args[0]}, args[1:]...)
	}
	fs := flag.NewFlagSet("php2shell-fix", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	php := fs.String("php", "", "Exact PHP CLI executable path (required for --apply)")
	ini := fs.String("ini", "", "Exact php.ini path; required for --apply")
	state := fs.String("state-dir", "", "Private backup directory (default: ~/.php2shell-fix)")
	jsonOutput := fs.Bool("json", false, "Emit a machine-readable JSON report")
	dry := fs.Bool("dry-run", false, "Preview remediation without changing files")
	apply := fs.Bool("apply", false, "Apply verified CVE-2026-115560 configuration mitigation only")
	verify := fs.Bool("verify", false, "Inspect effective PHP CLI configuration after changes")
	report := fs.Bool("report", false, "Emit complete machine-readable assessment")
	rollback := fs.String("rollback", "", "Restore one protected configuration backup by ID")
	scan := fs.Bool("scan", false, "Discover and assess PHP CLI installations")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "php2shell-fix: safe PHP2Shell inventory and conditional session mitigation\n\nCommands:\n  php2shell-fix scan [--php PATH] [--json]\n  php2shell-fix --dry-run --php PATH --ini PATH\n  php2shell-fix --apply --php PATH --ini PATH\n  php2shell-fix --verify --php PATH\n  php2shell-fix --rollback BACKUP-ID\n  php2shell-fix --report [--json]\n\n--apply does not upgrade PHP or remediate CVE-2026-109618/109619.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Unexpected arguments:", fs.Args())
		return 3
	}
	if *state == "" {
		v, err := mitigation.DefaultStateDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		*state = v
	}
	if *rollback != "" {
		if *apply || *dry || *verify || *report || *scan {
			fmt.Fprintln(os.Stderr, "Rollback must run alone")
			return 3
		}
		r, err := mitigation.Rollback(*rollback, *state)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Rollback refused:", err)
			return 3
		}
		fmt.Printf("Configuration restored from validated backup %s (%s). Restart and validate the real web worker separately.\n", r.ID, r.Target)
		return 0
	}
	if *apply && (*dry || *verify || *report || *scan) {
		fmt.Fprintln(os.Stderr, "Conflicting actions")
		return 3
	}
	if *apply && (*php == "" || *ini == "") {
		fmt.Fprintln(os.Stderr, "--apply requires both --php and --ini to bind to the inspected runtime")
		return 3
	}
	if *apply || *dry {
		if *php == "" || *ini == "" {
			fmt.Fprintln(os.Stderr, "--dry-run and --apply require explicit --php and --ini")
			return 3
		}
		p := inventory.Inspect(*php)
		if p.Error != "" {
			fmt.Fprintln(os.Stderr, "PHP inspection failed:", p.Error)
			return 3
		}
		if p.INI == "" || !sameFile(p.INI, *ini) {
			fmt.Fprintln(os.Stderr, "Selected php.ini does not match the PHP CLI loaded configuration; refusing modification")
			return 3
		}
		if !*apply {
			printReport(Report{Timestamp: time.Now().UTC().Format(time.RFC3339), HostOS: runtime.GOOS, Status: "DRY_RUN", Note: "Only an explicit configuration mitigation for CVE-2026-115560 is available; no PHP core security update is performed. Active web workers require separate validation.", Installations: []Installation{{PHP: p, Findings: assessment.Evaluate(p.Version, p.Provenance, p.UploadProgress)}}}, *jsonOutput)
			return 0
		}
		if disabled(p.UploadProgress) {
			fmt.Println("NO_OP: session.upload_progress already disabled for this PHP CLI configuration; web worker verification required.")
			return 0
		}
		r, err := mitigation.Apply(*ini, *state, func() error {
			got := inventory.Inspect(*php)
			if got.Error != "" {
				return errors.New(got.Error)
			}
			if !sameFile(got.INI, *ini) || !disabled(got.UploadProgress) {
				return errors.New("selected PHP CLI did not load the expected mitigation")
			}
			return nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "Remediation failed:", err)
			return 3
		}
		printReport(Report{Timestamp: time.Now().UTC().Format(time.RFC3339), HostOS: runtime.GOOS, Status: "MITIGATION_APPLIED_CLI_VALIDATED", Note: "CVE-2026-115560 conditional mitigation applied to php.ini. Restart and verify the real web worker. CVE-2026-109618 and CVE-2026-109619 still require official PHP/vendor security updates.", Action: &r, Installations: []Installation{}}, *jsonOutput)
		return 0
	}
	paths := inventory.Candidates(*php)
	res := Report{Timestamp: time.Now().UTC().Format(time.RFC3339), HostOS: runtime.GOOS, Status: "ASSESSMENT_ONLY", Note: "Only identified CLI installations were inspected. Active PHP-FPM, Apache, IIS/FastCGI, containers and vendor package backports require independent verification.", Installations: []Installation{}}
	if len(paths) == 0 {
		res.Status = "NO_PHP_CLI_FOUND"
	}
	for _, path := range paths {
		p := inventory.Inspect(path)
		inst := Installation{PHP: p}
		if p.Error == "" {
			inst.Findings = assessment.Evaluate(p.Version, p.Provenance, p.UploadProgress)
		}
		res.Installations = append(res.Installations, inst)
	}
	printReport(res, *jsonOutput || *report)
	return 0
}

func disabled(v string) bool {
	return strings.EqualFold(strings.TrimSpace(v), "off") || strings.TrimSpace(v) == "0" || strings.TrimSpace(v) == ""
}

func sameFile(a, b string) bool {
	a, ea := filepath.Abs(a)
	b, eb := filepath.Abs(b)
	if ea != nil || eb != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func printReport(r Report, jsonMode bool) {
	if jsonMode {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		return
	}
	fmt.Printf("Status: %s | Host: %s\n%s\n", r.Status, r.HostOS, r.Note)
	if r.Action != nil {
		fmt.Printf("Backup ID: %s\nUpdated: %s\n", r.Action.ID, r.Action.Target)
	}
	for _, install := range r.Installations {
		fmt.Printf("\nPHP: %s | %s | %s | ini: %s\n", install.Executable, install.Version, install.SAPI, install.INI)
		if install.Error != "" {
			fmt.Printf("  Inspection error: %s\n", install.Error)
		}
		for _, f := range install.Findings {
			fmt.Printf("  %s: %s (%s)\n", f.CVE, f.Status, f.Reason)
		}
	}
}
