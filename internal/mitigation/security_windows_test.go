package mitigation

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func setTestDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateDirectoryCreatedWithProtectedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := createPrivateDir(path); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivate(path, true); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL not protected: %v", err)
	}
	file := filepath.Join(path, "backup")
	if err := saveNew(file, []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivate(file, false); err != nil {
		t.Fatal(err)
	}
}

func TestExistingExplicitBroadACENotRepaired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := createPrivateDir(path); err != nil {
		t.Fatal(err)
	}
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	setTestDACL(t, path, "D:P(A;OICI;FA;;;"+sid.String()+")(A;;FR;;;WD)")
	if err := ensureStateDir(path); err == nil {
		t.Fatal("accepted Everyone read ACE")
	}
	if err := validatePrivate(path, true); err == nil {
		t.Fatal("silently removed explicit ACE")
	}
}

func TestAncestorDeleteChildAndInheritOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ancestor")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	base := "D:P(A;OICI;FA;;;" + sid.String() + ")"
	setTestDACL(t, path, base+"(A;;0x40;;;WD)")
	if err := validateACL(path, false); err == nil {
		t.Fatal("accepted foreign delete-child")
	}
	setTestDACL(t, path, base+"(A;OIIO;FA;;;WD)")
	if err := validateACL(path, false); err != nil {
		t.Fatal("inherit-only ACE applies incorrectly:", err)
	}
	if err := validateACL(path, true); err == nil {
		t.Fatal("private backups would inherit foreign ACE")
	}
}

func TestRollbackRejectsBroadRecoveryACL(t *testing.T) {
	for _, which := range []string{"record", "backup"} {
		t.Run(which, func(t *testing.T) {
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
			p := r.Backup
			if which == "record" {
				p = filepath.Join(state, r.ID+".json")
			}
			sid, err := currentSID()
			if err != nil {
				t.Fatal(err)
			}
			setTestDACL(t, p, "D:P(A;;FA;;;"+sid.String()+")(A;;FR;;;WD)")
			if _, err := Rollback(r.ID, state); err == nil {
				t.Fatal("accepted broad recovery ACL")
			}
			after, _ := os.ReadFile(ini)
			if string(before) != string(after) {
				t.Fatal("target changed on refusal")
			}
		})
	}
}

func TestTargetDACLPreservedDuringApplyAndRollback(t *testing.T) {
	root := t.TempDir()
	ini := filepath.Join(root, "php.ini")
	state := filepath.Join(root, "state")
	if err := os.WriteFile(ini, []byte("a=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	setTestDACL(t, ini, "D:P(A;;FA;;;"+sid.String()+")(A;;FR;;;BU)")
	read := func() string {
		t.Helper()
		sd, err := windows.GetNamedSecurityInfo(ini, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		return sd.String()
	}
	before := read()
	r, err := Apply(ini, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := read(); got != before {
		t.Fatalf("apply changed DACL: %s", got)
	}
	if _, err := Rollback(r.ID, state); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != before {
		t.Fatalf("rollback changed DACL: %s", got)
	}
}
