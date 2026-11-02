package assessment

import "testing"

func TestAssessBaselinesAndBackports(t *testing.T) {
	tests := []struct{ version, provenance, want string }{
		{"8.5.12", "unknown", "UPSTREAM_FIXED"}, {"8.4.27", "unknown", "UPSTREAM_FIXED"},
		{"8.3.36", "unknown", "UPSTREAM_FIXED"}, {"8.2.35", "unknown", "UPSTREAM_FIXED"},
		{"8.4.26", "unknown", "VENDOR_REVIEW_REQUIRED"}, {"8.4.26", "upstream", "UPSTREAM_OUTDATED"},
		{"8.1.34", "unknown", "EOL_OR_VENDOR_REVIEW"}, {"broken", "unknown", "UNKNOWN"},
	}
	for _, tc := range tests {
		if got := Evaluate(tc.version, tc.provenance, "On")[0].Status; got != tc.want {
			t.Errorf("%s %s: got %s want %s", tc.version, tc.provenance, got, tc.want)
		}
	}
}

func TestVersionStrict(t *testing.T) {
	for _, s := range []string{"8.4", "8.4.1;rm", "8.4.-1", "8.4.1-dev"} {
		if _, err := ParseVersion(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if _, err := ParseVersion("8.4.27"); err != nil {
		t.Fatal(err)
	}
}
