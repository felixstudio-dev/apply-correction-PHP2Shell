//go:build windows

package platform

import (
	"syscall"
	"unsafe"
)

// readWindowsProductType inspects the OS installation type without invoking
// reg.exe, requiring elevation, or changing the registry.
func readWindowsProductType() string {
	keyName, err := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Control\ProductOptions`)
	if err != nil {
		return ""
	}
	var key syscall.Handle
	if err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, keyName, 0, syscall.KEY_READ, &key); err != nil {
		return ""
	}
	defer syscall.RegCloseKey(key)
	valueName, err := syscall.UTF16PtrFromString("ProductType")
	if err != nil {
		return ""
	}
	var kind uint32
	var length uint32
	if err = syscall.RegQueryValueEx(key, valueName, nil, &kind, nil, &length); err != nil || kind != syscall.REG_SZ || length < 2 || length > 256 || length%2 != 0 {
		return ""
	}
	data := make([]uint16, length/2)
	if err = syscall.RegQueryValueEx(key, valueName, nil, &kind, (*byte)(unsafe.Pointer(&data[0])), &length); err != nil || kind != syscall.REG_SZ || length > uint32(len(data)*2) || length%2 != 0 {
		return ""
	}
	return syscall.UTF16ToString(data[:length/2])
}
