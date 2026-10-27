package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyReportsEffectiveCLIMitigation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake PHP process is a POSIX shell script; Windows is covered by cross-build checks")
	}
	for _, tc := range []struct {
		name     string
		progress string
		status   string
		code     int
	}{
		{"disabled-empty-ini-value", "", "CLI_MITIGATION_VERIFIED", 0},
		{"enabled", "1", "CLI_MITIGATION_NOT_APPLIED", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			php := fakePHP(t, map[string]string{
				"version": "8.2.35", "sapi": "cli", "ini": "/tmp/php2shell-test-php.ini", "progress": tc.progress,
			})
			code, output := captureRun(t, "--verify", "--php", php, "--json")
			if code != tc.code {
				t.Fatalf("exit code: got %d, want %d; report: %s", code, tc.code, output)
			}
			var report struct {
				Status        string `json:"status"`
				Installations []struct {
					UploadProgress *string `json:"upload_progress"`
				} `json:"installations"`
			}
			if err := json.Unmarshal([]byte(output), &report); err != nil {
				t.Fatal(err)
			}
			if report.Status != tc.status || len(report.Installations) != 1 || report.Installations[0].UploadProgress == nil || *report.Installations[0].UploadProgress != tc.progress {
				t.Fatalf("unexpected verification result: %+v", report)
			}
		})
	}
}

func TestVerifyRejectsIncompleteCLIInspection(t *testing.T) {
	if code, _ := captureRun(t, "--verify", "--json"); code != 3 {
		t.Fatalf("verification without explicit PHP must fail, got %d", code)
	}
	if code, _ := captureRun(t, "--verify", "--dry-run", "--php", "ignored", "--json"); code != 3 {
		t.Fatalf("conflicting actions must fail, got %d", code)
	}
	if runtime.GOOS == "windows" {
		return
	}
	for _, tc := range []struct {
		name   string
		fields map[string]string
	}{
		{"missing-progress-key", map[string]string{"version": "8.2.35", "sapi": "cli", "ini": "/tmp/php2shell-test-php.ini"}},
		{"missing-ini", map[string]string{"version": "8.2.35", "sapi": "cli", "progress": ""}},
		{"not-cli", map[string]string{"version": "8.2.35", "sapi": "fpm-fcgi", "ini": "/tmp/php2shell-test-php.ini", "progress": ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			php := fakePHP(t, tc.fields)
			if code, output := captureRun(t, "--verify", "--php", php, "--json"); code != 3 {
				t.Fatalf("incomplete/non-CLI inspection must fail closed: code=%d, report=%s", code, output)
			}
		})
	}
}

func TestScanDoesNotReportDisabledSettingWhenInspectionFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-php")
	code, output := captureRun(t, "--scan", "--php", missing, "--json")
	if code != 0 {
		t.Fatalf("read-only scan returned %d: %s", code, output)
	}
	var report struct {
		Installations []map[string]json.RawMessage `json:"installations"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Installations) != 1 {
		t.Fatalf("expected one failed inspection: %s", output)
	}
	if _, ok := report.Installations[0]["error"]; !ok {
		t.Fatalf("expected explicit inspection error: %s", output)
	}
	if _, ok := report.Installations[0]["upload_progress"]; ok {
		t.Fatalf("unobserved upload-progress setting must not appear: %s", output)
	}
}

func fakePHP(t *testing.T, fields map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "php-fake")
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' '" + string(b) + "'\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func captureRun(t *testing.T, args ...string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	before := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = before; _ = r.Close() }()
	code := run(args)
	_ = w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return code, strings.TrimSpace(string(b))
}
