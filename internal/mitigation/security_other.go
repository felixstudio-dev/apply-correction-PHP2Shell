//go:build !linux && !windows

package mitigation

import (
	"errors"
	"os"
)

func unsupported() error {
	return errors.New("secure configuration mutation is supported only on Linux and Windows")
}
func openRegular(string) (*os.File, error)                        { return nil, unsupported() }
func createPrivateDir(string) error                               { return unsupported() }
func validateAncestors(string) error                              { return unsupported() }
func validatePrivate(string, bool) error                          { return unsupported() }
func captureMetadata(string) (*fileMetadata, error)               { return nil, unsupported() }
func preserveMetadata(*os.File, *fileMetadata, os.FileMode) error { return unsupported() }
