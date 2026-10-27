package remediation

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeAPT struct {
	installed  string
	versions   map[string]string
	candidates map[string]string
	origin     string
	simulation string
	fail       string
}

func (f fakeAPT) Run(_ context.Context, executable string, args ...string) (string, error) {
	if strings.Contains(executable, f.fail) && f.fail != "" {
		return "", errors.New("fixture command failure")
	}
	switch executable {
	case "/usr/bin/dpkg-query":
		if len(args) > 0 && args[0] == "-S" {
			return "php8.4-cli: /usr/bin/php8.4\n", nil
		}
		return f.installed, nil
	case "/usr/bin/apt-cache":
		if len(args) != 2 {
			return "", errors.New("invalid policy request")
		}
		pkg := args[1]
		candidate := f.candidates[pkg]
		if candidate == "" {
			candidate = "(none)"
		}
		installed := f.versions[pkg]
		return pkg + ":\n  Installed: " + installed + "\n  Candidate: " + candidate + "\n  Version table:\n     " + candidate + " 500\n        500 " + f.origin + " noble/main amd64 Packages\n *** " + installed + " 100\n        100 /var/lib/dpkg/status\n", nil
	case "/usr/bin/dpkg":
		if len(args) != 4 || args[0] != "--compare-versions" {
			return "", errors.New("unexpected comparison command")
		}
		if args[1] == args[3] {
			return "", errors.New("version is unchanged")
		}
		return "", nil
	case "/usr/bin/apt-get":
		return f.simulation, nil
	default:
		return "", errors.New("unexpected external command")
	}
}

func goodFixture() fakeAPT {
	return fakeAPT{
		installed:  "ii \tphp8.4-cli\t8.4.26-1\nii \tphp8.4-common\t8.4.26-1\nii \tphp8.3-cli\t8.3.35-1\n",
		versions:   map[string]string{"php8.4-cli": "8.4.26-1", "php8.4-common": "8.4.26-1"},
		candidates: map[string]string{"php8.4-cli": "8.4.27-1", "php8.4-common": "8.4.27-1"},
		origin:     "http://archive.ubuntu.com/ubuntu",
		simulation: "Reading package lists... Done\nInst php8.4-cli [8.4.26-1] (8.4.27-1 Ubuntu:24.04)\nInst php8.4-common [8.4.26-1] (8.4.27-1 Ubuntu:24.04)\nConf php8.4-common (8.4.27-1 Ubuntu:24.04)\n",
	}
}

func TestPlanAPTEvidence(t *testing.T) {
	plan, err := PlanAPT(context.Background(), "ubuntu", "8.4.26", goodFixture())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != "ELIGIBLE_FOR_ADMIN_REVIEW" {
		t.Fatalf("status=%s reasons=%v", plan.Status, plan.Reasons)
	}
	if len(plan.Packages) != 2 || len(plan.PreviewCommand) != 7 {
		t.Fatalf("unexpected package count or proposed command: %+v", plan)
	}
	for _, p := range plan.Packages {
		if p.Origin != "Ubuntu" || p.FixStatus != "CANDIDATE_MEETS_UPSTREAM_FLOOR" {
			t.Fatalf("candidate not verified: %+v", p)
		}
	}
}

func TestPlanAPTRefusesUnverifiedPackages(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fakeAPT)
		want   string
	}{
		{"backport-needs-advisory", func(f *fakeAPT) { f.candidates["php8.4-cli"] = "8.4.26-2" }, "VENDOR_ADVISORY_REQUIRED"},
		{"untrusted-origin", func(f *fakeAPT) { f.origin = "http://unverified.example.com/ubuntu" }, "PACKAGE_ORIGIN_REVIEW_REQUIRED"},
		{"remove-package", func(f *fakeAPT) { f.simulation = "Remv php8.4-common [8.4.26-1]" }, "DEPENDENCY_CHANGES_REQUIRE_REVIEW"},
		{"unrelated-install", func(f *fakeAPT) { f.simulation = "Inst openssl [1] (2 Ubuntu:24.04)" }, "DEPENDENCY_CHANGES_REQUIRE_REVIEW"},
		{"missing-simulated-upgrade", func(f *fakeAPT) { f.simulation = "Inst php8.4-cli [8.4.26-1] (8.4.27-1 Ubuntu:24.04)" }, "SIMULATION_INCOMPLETE"},
		{"no-cli", func(f *fakeAPT) { f.installed = "ii \tphp8.4-common\t8.4.26-1\n" }, "PACKAGE_PROVENANCE_UNVERIFIED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := goodFixture()
			tc.mutate(&f)
			p, err := PlanAPT(context.Background(), "ubuntu", "8.4.26", f)
			if err != nil {
				t.Fatal(err)
			}
			if p.Status != tc.want {
				t.Fatalf("got %s want %s: %+v", p.Status, tc.want, p)
			}
		})
	}
}

func TestPlanAPTFailsClosedForUnsupportedAndErrors(t *testing.T) {
	p, err := PlanAPT(context.Background(), "almalinux", "8.4.26", goodFixture())
	if err != nil || p.Status != "UNSUPPORTED" {
		t.Fatalf("unsupported distribution: %+v %v", p, err)
	}
	p, err = PlanAPT(context.Background(), "ubuntu", "8.1.0", goodFixture())
	if err != nil || p.Status != "UNSUPPORTED" {
		t.Fatalf("unknown PHP floor: %+v %v", p, err)
	}
	f := goodFixture()
	f.fail = "dpkg-query"
	if _, err = PlanAPT(context.Background(), "ubuntu", "8.4.26", f); err == nil {
		t.Fatal("missing package query was accepted")
	}
}

func TestCandidateOriginBoundToCandidateStanza(t *testing.T) {
	f := goodFixture()
	f.origin = "http://untrusted.invalid/ubuntu"
	policy, err := f.Run(context.Background(), "/usr/bin/apt-cache", "policy", "php8.4-cli")
	if err != nil {
		t.Fatal(err)
	}
	policy += "     8.4.24-1 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n"
	if got := candidateOrigin(policy, "8.4.27-1"); got != "UNVERIFIED" {
		t.Fatalf("trusted an unrelated version: %s", got)
	}
}

func TestCandidateOriginRejectsMixedSources(t *testing.T) {
	f := goodFixture()
	policy, err := f.Run(context.Background(), "/usr/bin/apt-cache", "policy", "php8.4-cli")
	if err != nil {
		t.Fatal(err)
	}
	policy = strings.Replace(policy, " *** 8.4.26-1 100", "        300 https://evil.invalid/ubuntu noble/main amd64 Packages\n *** 8.4.26-1 100", 1)
	if got := candidateOrigin(policy, "8.4.27-1"); got != "UNVERIFIED" {
		t.Fatalf("accepted mixed repository sources: %s", got)
	}
}
