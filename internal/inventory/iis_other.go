//go:build !windows

package inventory

func DetectIIS() *IISReport { return nil }
