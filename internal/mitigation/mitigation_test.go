package mitigation

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMitigationBackupRollbackAndIdempotency(t *testing.T) {
	root := t.TempDir()
	ini := filepath.Join(root, "php.ini")
	state := filepath.Join(root, "state")
	original := []byte("memory_limit=128M\nsession.upload_progress.enabled=On\n")
	if err := os.WriteFile(ini, original, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Apply(ini, state, func() error {
		b, err := os.ReadFile(ini)
		if err != nil {
			return err
		}
		if !strings.Contains(string(b), "session.upload_progress.enabled=Off") {
			t.Fatal("mitigation missing")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !r.CLIValidated {
		t.Fatal("validation flag missing")
	}
	if _, err := Apply(ini, state, nil); err == nil {
		t.Fatal("duplicate marker unexpectedly applied")
	}
	recovered, err := Rollback(r.ID, state)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.RolledBack {
		t.Fatal("rollback state missing")
	}
	b, err := os.ReadFile(ini)
	if err != nil || string(b) != string(original) {
		t.Fatalf("round-trip failed: %v", err)
	}
	if _, err := Rollback(r.ID, state); err != nil {
		t.Fatalf("idempotent rollback: %v", err)
	}
}

func TestRollbackProtectsOutsideEdits(t *testing.T) {
	root := t.TempDir()
	ini := filepath.Join(root, "php.ini")
	state := filepath.Join(root, "state")
	if err := os.WriteFile(ini, []byte("a=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Apply(ini, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ini, []byte("a=2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(r.ID, state); err == nil {
		t.Fatal("overwrote independent change")
	}
	if _, err := Rollback("../../bad", state); err == nil {
		t.Fatal("accepted path traversal")
	}
	if err := os.WriteFile(r.Backup, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(r.ID, state); err == nil {
		t.Fatal("accepted invalid backup hash")
	}
}

func TestPatchPreservesLineEndings(t *testing.T) {
	original := []byte("foo=bar\r\n")
	b, changed := PatchUploadProgress(original)
	if !changed || !strings.Contains(string(b), "\r\nsession.upload_progress.enabled=Off\r\n") {
		t.Fatal("CRLF formatting lost")
	}
	if _, changed = PatchUploadProgress(b); changed {
		t.Fatal("patch must be idempotent")
	}
}

func TestFailedPostCheckRestoresOriginal(t *testing.T) {
	root := t.TempDir()
	ini := filepath.Join(root, "php.ini")
	before := []byte("session.upload_progress.enabled=On\n")
	if err := os.WriteFile(ini, before, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(ini, filepath.Join(root, "state"), func() error { return errors.New("simulated verification failure") }); err == nil {
		t.Fatal("verification failure was ignored")
	}
	after, err := os.ReadFile(ini)
	if err != nil || string(after) != string(before) {
		t.Fatalf("original configuration not restored: %v", err)
	}
}

func TestExclusiveLockAndLinkRejection(t *testing.T) {
	root := t.TempDir()
	ini := filepath.Join(root, "php.ini")
	if err := os.WriteFile(ini, []byte("x=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	if err := ensureStateDir(state); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockDir(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(ini, state, nil); err == nil {
		t.Fatal("concurrent writer was allowed")
	}
	unlock()
	link := filepath.Join(root, "linked.ini")
	if err := os.Symlink(ini, link); err == nil {
		if _, err := Apply(link, state, nil); err == nil {
			t.Fatal("symlink target was modified")
		}
	}
}
