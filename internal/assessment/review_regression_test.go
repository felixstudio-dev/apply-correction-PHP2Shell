package assessment

import "testing"

func TestObservedEmptyUploadProgressIsMitigated(t *testing.T) {
	for _, value := range []string{"", "0", "Off", " off "} {
		findings := Evaluate("8.2.35", "unknown", value)
		if findings[2].Status != "CLI_MITIGATED" {
			t.Fatalf("observed %q: %s", value, findings[2].Status)
		}
	}
	if got := Evaluate("8.2.35", "unknown", "1")[2].Status; got != "CONDITIONAL_REVIEW" {
		t.Fatal(got)
	}
}
