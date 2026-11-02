package remediation

import (
	"context"
	"strings"
	"testing"
)

func TestPlanRejectsEveryUnrecognizedCandidateSource(t *testing.T) {
	for _, source := range []string{"ftp://foreign.invalid/archive", "mirror://foreign.invalid/list", "copy:/srv/archive", "cdrom:[Synthetic]", "https+tor://foreign.invalid/archive", "/srv/local-archive"} {
		t.Run(source, func(t *testing.T) {
			f := goodFixture()
			f.origin += " noble/main amd64 Packages\n        300 " + source
			plan, err := PlanAPT(context.Background(), "ubuntu", "8.4.26", f)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Status != "PACKAGE_ORIGIN_REVIEW_REQUIRED" {
				t.Fatalf("accepted mixed source %q: %s", source, plan.Status)
			}
		})
	}
	f := goodFixture()
	f.origin += " noble/main amd64 Packages\n        -1 ftp://foreign.invalid/archive"
	plan, err := PlanAPT(context.Background(), "ubuntu", "8.4.26", f)
	if err != nil || plan.Status != "PACKAGE_ORIGIN_REVIEW_REQUIRED" {
		t.Fatalf("negative priority source escaped validation: %+v %v", plan, err)
	}
	f = goodFixture()
	policy, _ := f.Run(context.Background(), "/usr/bin/apt-cache", "policy", "php8.4-cli")
	policy = strings.Replace(policy, " *** 8.4.26-1 100", "        100 /var/lib/dpkg/status\n *** 8.4.26-1 100", 1)
	if got := candidateOrigin(policy, "8.4.27-1"); got != "Ubuntu" {
		t.Fatalf("local status should be allowed: %s", got)
	}
}
