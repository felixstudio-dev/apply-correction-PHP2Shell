package mitigation

import (
	"encoding/binary"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPOSIXACLAndOwnershipPreserved(t *testing.T) {
	root := t.TempDir()
	ini := filepath.Join(root, "php.ini")
	if err := os.WriteFile(ini, []byte("a=1\n"), 0640); err != nil {
		t.Fatal(err)
	}
	// Linux ACL wire format: owner, named user, group, mask, other.
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl, 2)
	entries := [][3]uint32{{1, 6, 0xffffffff}, {2, 4, 12345}, {4, 4, 0xffffffff}, {16, 4, 0xffffffff}, {32, 0, 0xffffffff}}
	for i, e := range entries {
		b := acl[4+i*8:]
		binary.LittleEndian.PutUint16(b, uint16(e[0]))
		binary.LittleEndian.PutUint16(b[2:], uint16(e[1]))
		binary.LittleEndian.PutUint32(b[4:], e[2])
	}
	if err := unix.Setxattr(ini, "system.posix_acl_access", acl, 0); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(ini, 12345, 12345); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := captureMetadata(ini)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Apply(ini, filepath.Join(root, "state"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireMetadata(ini, expected); err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(r.ID, filepath.Join(root, "state")); err != nil {
		t.Fatal(err)
	}
	if err := requireMetadata(ini, expected); err != nil {
		t.Fatal(err)
	}
}

func TestForeignOwnerStateRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("foreign-owner fixture requires root in isolated namespace")
	}
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(state, 12345, 12345); err != nil {
		t.Fatal(err)
	}
	if err := ensureStateDir(state); err == nil {
		t.Fatal("accepted foreign owner")
	}
	var st unix.Stat_t
	if err := unix.Lstat(state, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != 12345 {
		t.Fatal("silently changed owner")
	}
}

func TestUnpreservableMetadataLeavesOriginal(t *testing.T) {
	root := t.TempDir()
	ini := filepath.Join(root, "php.ini")
	if err := os.WriteFile(ini, []byte("a=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ini, os.ModeSetuid|0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(ini, filepath.Join(root, "state"), nil); err == nil {
		t.Fatal("accepted unsupported special mode")
	}
	b, _ := os.ReadFile(ini)
	if string(b) != "a=1\n" {
		t.Fatal("target changed on metadata refusal")
	}
}

func TestMetadataSurvivesApplyRollbackAndFailedValidation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		root := t.TempDir()
		ini := filepath.Join(root, "php.ini")
		if err := os.WriteFile(ini, []byte("a=1\n"), 0640); err != nil {
			t.Fatal(err)
		}
		if err := unix.Setxattr(ini, "user.php2shell_fixture", []byte("retain me"), 0); err != nil {
			t.Fatal(err)
		}
		expected, err := captureMetadata(ini)
		if err != nil {
			t.Fatal(err)
		}
		var validate func() error
		if fail {
			validate = func() error { return os.ErrInvalid }
		}
		r, err := Apply(ini, filepath.Join(root, "state"), validate)
		if fail {
			if err == nil {
				t.Fatal("accepted failed validation")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if err := requireMetadata(ini, expected); err != nil {
				t.Fatal(err)
			}
			if _, err := Rollback(r.ID, filepath.Join(root, "state")); err != nil {
				t.Fatal(err)
			}
		}
		actual, err := captureMetadata(ini)
		if err != nil || !reflect.DeepEqual(expected, actual) {
			t.Fatalf("metadata lost: %v", err)
		}
		b, _ := os.ReadFile(ini)
		if string(b) != "a=1\n" {
			t.Fatal("content not restored")
		}
	}
}

func TestRejectsUnsafeStateWithoutRepair(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0777); err != nil {
		t.Fatal(err)
	}
	if err := ensureStateDir(state); err == nil {
		t.Fatal("accepted broad state")
	}
	st, _ := os.Stat(state)
	if st.Mode().Perm() != 0777 {
		t.Fatal("silently repaired state")
	}
}

func TestRollbackRejectsUntrustedRecoveryFiles(t *testing.T) {
	for _, name := range []string{"record", "backup", "state", "ancestor", "metadata", "already-restored-metadata"} {
		t.Run(name, func(t *testing.T) {
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
			before, _ := os.ReadFile(ini)
			switch name {
			case "record":
				err = os.Chmod(filepath.Join(state, r.ID+".json"), 0666)
			case "backup":
				err = os.Chmod(r.Backup, 0644)
			case "state":
				err = os.Chmod(state, 0755)
			case "ancestor":
				err = os.Chmod(root, 0777)
				defer os.Chmod(root, 0700)
			case "metadata":
				err = unix.Setxattr(ini, "user.changed", []byte("outside edit"), 0)
			case "already-restored-metadata":
				if err := os.WriteFile(ini, []byte("a=1\n"), 0600); err != nil {
					t.Fatal(err)
				}
				before = []byte("a=1\n")
				err = unix.Setxattr(ini, "user.changed", []byte("outside edit"), 0)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Rollback(r.ID, state); err == nil {
				t.Fatal("untrusted rollback accepted")
			}
			after, _ := os.ReadFile(ini)
			if string(before) != string(after) {
				t.Fatal("target changed on refusal")
			}
		})
	}
}

func TestRejectsRecoverySymlinksAndHardlinks(t *testing.T) {
	for _, hard := range []bool{false, true} {
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
		rec := filepath.Join(state, r.ID+".json")
		moved := filepath.Join(root, "record")
		if err := os.Rename(rec, moved); err != nil {
			t.Fatal(err)
		}
		if hard {
			err = os.Link(moved, rec)
		} else {
			err = os.Symlink(moved, rec)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Rollback(r.ID, state); err == nil {
			t.Fatal("linked record accepted")
		}
	}
}
