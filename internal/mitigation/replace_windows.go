//go:build windows

package mitigation

import (
	"fmt"
	"syscall"
	"unsafe"
)

func replaceFile(from, to string) error {
	fromPtr, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	// ReplaceFileW preserves the destination DACL and security attributes.
	// Never ignore ACL merge failures when touching a privileged php.ini.
	fn := syscall.NewLazyDLL("kernel32.dll").NewProc("ReplaceFileW")
	r, _, callErr := fn.Call(uintptr(unsafe.Pointer(toPtr)), uintptr(unsafe.Pointer(fromPtr)), 0, 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("ReplaceFileW failed: %v", callErr)
	}
	return nil
}
