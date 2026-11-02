package mitigation

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

func createPrivateDir(path string) error { return os.Mkdir(path, 0700) }

func openRegular(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		unix.Close(fd)
		return nil, errors.New("not a regular single-link file")
	}
	return os.NewFile(uintptr(fd), path), nil
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
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
			return errors.New("untrusted directory owner or type")
		}
		if st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0) {
			return errors.New("untrusted writable ancestor")
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
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	kind := uint32(unix.S_IFREG)
	if dir {
		kind = unix.S_IFDIR
	}
	if st.Mode&unix.S_IFMT != kind || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 || (!dir && st.Nlink != 1) {
		return errors.New("untrusted backup ownership, permissions, links or type")
	}
	return nil
}

func captureMetadata(path string) (*fileMetadata, error) {
	if err := validateAncestors(filepath.Dir(path)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	return metadataFD(fd)
}

func metadataFD(fd int) (*fileMetadata, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&07000 != 0 {
		return nil, errors.New("unsupported configuration type, hard links or special mode")
	}
	m := &fileMetadata{UID: st.Uid, GID: st.Gid, Mode: st.Mode & 0777, Xattrs: map[string][]byte{}}
	n, err := unix.Flistxattr(fd, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate metadata: %w", err)
	}
	if n > 1<<20 {
		return nil, errors.New("metadata exceeds limit")
	}
	if n == 0 {
		return m, nil
	}
	names := make([]byte, n)
	n, err = unix.Flistxattr(fd, names)
	if err != nil {
		return nil, err
	}
	for _, name := range strings.Split(string(names[:n]), "\x00") {
		if name == "" {
			continue
		}
		if name == "security.ima" || name == "security.evm" {
			return nil, errors.New("content integrity metadata requires vendor-managed updates")
		}
		size, err := unix.Fgetxattr(fd, name, nil)
		if err != nil {
			return nil, err
		}
		if size > 1<<20 {
			return nil, errors.New("metadata exceeds limit")
		}
		value := make([]byte, size)
		got, err := unix.Fgetxattr(fd, name, value)
		if err != nil {
			return nil, err
		}
		if got != size {
			return nil, errors.New("metadata changed during inspection")
		}
		m.Xattrs[name] = value
	}
	return m, nil
}

func preserveMetadata(f *os.File, m *fileMetadata, mode os.FileMode) error {
	if m == nil {
		return errors.New("missing configuration metadata")
	}
	if uint32(mode.Perm()) != m.Mode {
		return errors.New("configuration mode changed")
	}
	fd := int(f.Fd())
	if err := f.Chown(int(m.UID), int(m.GID)); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	current, err := metadataFD(fd)
	if err != nil {
		return err
	}
	for name := range current.Xattrs {
		if _, ok := m.Xattrs[name]; !ok {
			if err := unix.Fremovexattr(fd, name); err != nil {
				return err
			}
		}
	}
	for name, value := range m.Xattrs {
		if err := unix.Fsetxattr(fd, name, value, 0); err != nil {
			return err
		}
	}
	actual, err := metadataFD(fd)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, m) {
		return errors.New("metadata preservation verification failed")
	}
	return nil
}
