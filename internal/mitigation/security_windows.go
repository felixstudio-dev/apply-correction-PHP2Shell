package mitigation

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

func currentSID() (*windows.SID, error) {
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return token.User.Sid, nil
}

func openChecked(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return windows.InvalidHandle, err
	}
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err == nil {
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && info.NumberOfLinks != 1) {
			err = errors.New("reparse point or hard-linked file refused")
		}
	}
	if err != nil {
		windows.CloseHandle(h)
		return windows.InvalidHandle, err
	}
	return h, nil
}

func openRegular(path string) (*os.File, error) {
	h, err := openChecked(path, windows.GENERIC_READ)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func createPrivateDir(path string) error {
	sid, err := currentSID()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;OICI;FA;;;" + sid.String() + ")")
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	return windows.CreateDirectory(p, &sa)
}

func trustedSID(sid, current *windows.SID) bool {
	// Windows servicing owns standard volume roots on some installations.
	const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	return sid.Equals(current) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.String() == trustedInstaller
}

// Elevated tokens can default to Administrators ownership. Set owner and DACL
// at creation for every recovery/temporary file, not only the state directory.
func createPrivateFile(path string) (*os.File, error) {
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;;FA;;;" + sid.String() + ")")
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// Fail closed on unfamiliar ACE forms. Do not attempt to repair an existing DACL.
func validateACL(path string, private bool) error {
	current, err := currentSID()
	if err != nil {
		return err
	}
	h, err := openChecked(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || (!private && !trustedSID(owner, current)) || (private && !owner.Equals(current)) {
		return errors.New("untrusted backup or ancestor owner")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil {
		return errors.New("unrestricted DACL refused")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported ACE type")
		}
		// Inherit-only grants do not affect ancestors, but must not expose new backups.
		if !private && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if trustedSID(sid, current) {
			continue
		}
		const fileDeleteChild = 0x0040
		dangerous := uint32(windows.DELETE | fileDeleteChild | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_ALL | windows.GENERIC_WRITE)
		// A volume root cannot itself be unlinked. DELETE_CHILD still matters.
		if filepath.Dir(path) == path {
			dangerous &^= windows.DELETE
		}
		if private || uint32(ace.Mask)&dangerous != 0 {
			return errors.New("backup or ancestor grants access to an untrusted principal")
		}
	}
	return nil
}

func validateAncestors(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if err := checkNoLinks(path); err != nil {
		return err
	}
	for {
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !st.IsDir() {
			return errors.New("ancestor is not a directory")
		}
		if err := validateACL(path, false); err != nil {
			return err
		}
		if path == filepath.Dir(path) {
			return nil
		}
		path = filepath.Dir(path)
	}
}

func validatePrivate(path string, dir bool) error {
	if err := checkNoLinks(path); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.IsDir() != dir || (!dir && !st.Mode().IsRegular()) {
		return errors.New("invalid backup object type")
	}
	return validateACL(path, true)
}

// ReplaceFileW preserves destination security metadata; Linux metadata records do not apply.
func captureMetadata(string) (*fileMetadata, error)                        { return nil, nil }
func preserveMetadata(f *os.File, _ *fileMetadata, mode os.FileMode) error { return f.Chmod(mode) }
