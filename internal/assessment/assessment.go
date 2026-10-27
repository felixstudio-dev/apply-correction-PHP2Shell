package assessment

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	CVEOne     = "CVE-2026-109618"
	CVETwo     = "CVE-2026-109619"
	CVESession = "CVE-2026-115560"
)

type Finding struct {
	CVE       string `json:"cve"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Reference string `json:"reference"`
}

type Version struct{ Major, Minor, Patch int }

func ParseVersion(s string) (Version, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("expected major.minor.patch: %q", s)
	}
	var v Version
	fields := []*int{&v.Major, &v.Minor, &v.Patch}
	for i, part := range parts {
		if part == "" {
			return Version{}, fmt.Errorf("empty version component")
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return Version{}, fmt.Errorf("invalid version component %q", part)
			}
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return Version{}, err
		}
		*fields[i] = n
	}
	return v, nil
}

// Evaluate conservatively: vendor packages may contain fixes backported to older version strings.
func Evaluate(version, provenance, uploadProgress string) []Finding {
	base := []Finding{}
	v, err := ParseVersion(version)
	status := "UNKNOWN"
	reason := "Cannot establish upstream patch status from this version"
	if err == nil {
		fixedPatch := map[[2]int]int{{8, 2}: 35, {8, 3}: 36, {8, 4}: 27, {8, 5}: 12}
		if min, ok := fixedPatch[[2]int{v.Major, v.Minor}]; ok {
			if v.Patch >= min {
				status, reason = "UPSTREAM_FIXED", "At or beyond the upstream security release on this branch; active web workers are not verified"
			} else if provenance == "upstream" {
				status, reason = "UPSTREAM_OUTDATED", fmt.Sprintf("Upstream PHP %d.%d requires at least %d.%d.%d", v.Major, v.Minor, v.Major, v.Minor, min)
			} else {
				status, reason = "VENDOR_REVIEW_REQUIRED", "Version predates the upstream fix; a vendor security backport may be present"
			}
		} else if v.Major < 8 || (v.Major == 8 && v.Minor < 2) {
			status, reason = "EOL_OR_VENDOR_REVIEW", "No maintained upstream security release on this branch; verify vendor backports or migrate"
		} else {
			status, reason = "UNKNOWN", "This branch has no verified security baseline in the current advisory catalog"
		}
	}
	for _, entry := range []struct{ cve, ref string }{
		{CVEOne, "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"},
		{CVETwo, "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"},
	} {
		base = append(base, Finding{entry.cve, status, reason, entry.ref})
	}
	sStatus, sReason := "CONDITIONAL_REVIEW", "Risk depends on application changing session.serialize_handler at runtime before session_start; current CLI settings cannot establish that behavior"
	if strings.EqualFold(strings.TrimSpace(uploadProgress), "off") || uploadProgress == "0" {
		sStatus, sReason = "CLI_MITIGATED", "Session upload progress is disabled for the inspected CLI configuration; web-worker settings still require verification"
	}
	base = append(base, Finding{CVESession, sStatus, sReason, "https://www.php.net/"})
	return base
}
