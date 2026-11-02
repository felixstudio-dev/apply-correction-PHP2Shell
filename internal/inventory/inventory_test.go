package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDiscoveryIncludesVersionedHostingCLIPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux hosting layout")
	}
	root := t.TempDir()
	old := linuxPatterns
	defer func() { linuxPatterns = old }()
	linuxPatterns = nil
	for _, pattern := range old {
		linuxPatterns = append(linuxPatterns, filepath.Join(root, pattern))
	}
	t.Setenv("PATH", "")
	expected := map[string]bool{}
	for _, rel := range []string{"opt/cpanel/ea-php74/root/usr/bin/php", "opt/cpanel/ea-php83/root/usr/bin/php", "opt/alt/php74/usr/bin/php"} {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0700); err != nil {
			t.Fatal(err)
		}
		expected[path] = true
	}
	for _, path := range Candidates("") {
		delete(expected, path)
	}
	if len(expected) != 0 {
		t.Fatalf("missing hosting CLI paths: %v", expected)
	}
	explicit := filepath.Join(root, "only-this")
	got := Candidates(explicit)
	if len(got) != 1 || got[0] != explicit {
		t.Fatal("explicit selection broadened")
	}
}
