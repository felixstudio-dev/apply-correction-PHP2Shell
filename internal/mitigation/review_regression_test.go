package mitigation

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyRelativeStateRecordRemainsRecoverable(t *testing.T) {
	root := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	ini := filepath.Join(root, "php.ini")
	if err := os.WriteFile(ini, []byte("a=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Apply(ini, "state", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Backup = filepath.Join("state", r.ID+".ini.bak")
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicReplace(filepath.Join(root, "state", r.ID+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	recovered, err := Rollback(r.ID, filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(recovered.Backup) {
		t.Fatal("legacy path not normalized after validated recovery")
	}
}

func TestPatchPrecedesScopesAndPreservesContents(t *testing.T) {
	for _, section := range []string{"[PATH=/srv/synthetic]", "[HOST = example.invalid]"} {
		prefix := "example=\"first\n[PATH=/not-a-section]\nlast\"\r\nsession.upload_progress.enabled=On\r\n"
		suffix := section + "\r\nmemory_limit=128M\r\n"
		got, changed := PatchUploadProgress([]byte(prefix + suffix))
		if !changed || !strings.HasPrefix(string(got), prefix) || !strings.HasSuffix(string(got), suffix) {
			t.Fatal("original contents changed")
		}
		if strings.Index(string(got), "enabled=Off") > strings.LastIndex(string(got), section) {
			t.Fatal("mitigation remained scoped")
		}
	}
}

func TestSectionNameWhitespaceRemainsSignificant(t *testing.T) {
	for _, section := range []string{"[ PATH=/srv/synthetic]", "[\tHOST=example.invalid]", "[\" PATH=/srv/synthetic\"]"} {
		original := []byte(section + "\nsession.upload_progress.enabled=On\n")
		patched, _ := PatchUploadProgress(original)
		if !strings.HasPrefix(string(patched), string(original)) {
			t.Fatalf("ordinary section misclassified: %q", section)
		}
	}
}
func bareSectionFixtures() []string {
	return []string{"[PATH]\nsession.upload_progress.enabled=On", "[HOST]\nsession.upload_progress.enabled=On", "[\"PATH\"]\nsession.upload_progress.enabled=On", "['HOST']\nsession.upload_progress.enabled=On", "[path]; comment\nsession.upload_progress.enabled=On", "[\"host\"] ; comment\nsession.upload_progress.enabled=On"}
}

func TestBareSectionNamesRemainGlobal(t *testing.T) {
	for _, section := range bareSectionFixtures() {
		original := []byte(section + "\n")
		patched, _ := PatchUploadProgress(original)
		if !strings.HasPrefix(string(patched), string(original)) {
			t.Errorf("ordinary section misclassified: %q", section)
		}
	}
}
func TestScopedINIMitigationWithRealPHP(t *testing.T) {
	php := os.Getenv("PHP2SHELL_TEST_PHP")
	if php == "" {
		t.Skip("set PHP2SHELL_TEST_PHP for real CLI integration")
	}
	for _, section := range append([]string{"[PATH=/srv/synthetic]", "[HOST=example.invalid]", "[PATH = /srv/synthetic]", "[HOST = example.invalid]", "example=\"C:\\path\\\"\n[PATH=/srv/synthetic]", "example='C:\\path\\'\n[HOST=example.invalid]", "[PATH=/srv/synthetic]\n[PHP]\nsession.upload_progress.enabled=On", "example=#\"first\n[PATH=/not-a-section]\nlast\"\n[HOST=example.invalid]", "[ PATH=/srv/synthetic]\nsession.upload_progress.enabled=On", "[\tHOST=example.invalid]\nsession.upload_progress.enabled=On", "[\" PATH=/srv/synthetic\"]\nsession.upload_progress.enabled=On", "[\"PATH'\"]", "['HOST\"']", "[PATH \"\"]", "['PATH' ]", "[\"PATH\" \"=/srv/synthetic\"]"}, append(bareSectionFixtures(), quotedSectionFixtures()...)...) {
		root := t.TempDir()
		ini := filepath.Join(root, "php.ini")
		original := []byte("session.upload_progress.enabled=On\n" + section + "\nmemory_limit=128M\n")
		if err := os.WriteFile(ini, original, 0600); err != nil {
			t.Fatal(err)
		}
		inspect := func() string {
			t.Helper()
			cmd := exec.Command(php, "-c", ini, "-r", `echo json_encode(ini_get('session.upload_progress.enabled'));`)
			cmd.Env = append(os.Environ(), "PHP_INI_SCAN_DIR="+root)
			b, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("PHP: %v %s", err, b)
			}
			return string(b)
		}
		if got := inspect(); got != `"1"` {
			t.Fatalf("baseline: %s", got)
		}
		record, err := Apply(ini, filepath.Join(root, "state"), func() error {
			if got := inspect(); got != `""` && got != `"0"` {
				return os.ErrInvalid
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Rollback(record.ID, filepath.Join(root, "state")); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(ini)
		if string(b) != string(original) || inspect() != `"1"` {
			t.Fatal("rollback mismatch")
		}
	}
}

func TestRelativeStateRecoveryFromDifferentDirectory(t *testing.T) {
	root := t.TempDir()
	elsewhere := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(previous); err != nil {
			t.Error(err)
		}
	}()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	ini := filepath.Join(root, "php.ini")
	if err := os.WriteFile(ini, []byte("a=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	record, err := Apply(ini, "state", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(record.Backup) {
		t.Errorf("relative backup persisted: %s", record.Backup)
	}
	if err := os.Chdir(elsewhere); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecord(record.ID, filepath.Join(root, "state")); err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(record.ID, filepath.Join(root, "state")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(ini)
	if string(b) != "a=1\n" {
		t.Fatal("rollback mismatch")
	}
}

func quotedSectionFixtures() []string {
	return []string{
		"[\"PATH\" ]\nsession.upload_progress.enabled=On",
		"[\"HOST\"\t]\nsession.upload_progress.enabled=On",
		"[\"PATH\" \"\"]\nsession.upload_progress.enabled=On",
		"[\"PA\" \"TH\"]\nsession.upload_progress.enabled=On",
		"[ \"HOST\" ]\nsession.upload_progress.enabled=On",
		"['PA''TH']\nsession.upload_progress.enabled=On", "[\"PA\" TH]\nsession.upload_progress.enabled=On", "[PA \"TH\"]\nsession.upload_progress.enabled=On", "[\" PATH\" ]\nsession.upload_progress.enabled=On",
	}
}
func TestQuotedSectionTokensRemainGlobal(t *testing.T) {
	for _, section := range quotedSectionFixtures() {
		original := []byte(section + "\n")
		patched, _ := PatchUploadProgress(original)
		if !strings.HasPrefix(string(patched), string(original)) {
			t.Errorf("ordinary section misclassified: %q", section)
		}
	}
}

func TestLiteralSectionTokens(t *testing.T) {
	for text, want := range map[string]string{
		"\"PATH\" ]": "PATH", "\"PATH\" \"\"]": "PATH",
		"PA \"TH\"]": "PA TH", "\"PA\" TH]": "PATH",
		"PATH \"\"]": "PATH ", "'PATH' ]": "PATH ",
		" \"HOST\"]": "HOST", "\" PATH\" ]": " PATH",
		"\"PATH'\"]": "PATH'", "'HOST\"']": "HOST\"",
		"\"PATH=\\\"x\\\"\"]": "PATH=\"x\"",
		"\"PATH=]x\"]":        "PATH=]x",
	} {
		if got := literalSectionName(text); got != want {
			t.Errorf("%q: got %q, want %q", text, got, want)
		}
	}
}
