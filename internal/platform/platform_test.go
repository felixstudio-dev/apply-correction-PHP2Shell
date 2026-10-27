package platform

import (
	"strings"
	"testing"
)

func TestDescribeMajorPlatformFamilies(t *testing.T) {
	cases := []struct {
		name, goos, release, family, manager, planning, status string
		available                                              []string
	}{
		{"debian", "linux", "ID=debian\nVERSION_ID=12", "debian", "apt-get", "APT_READ_ONLY", "PARTIALLY_SUPPORTED", []string{"apt-get", "apt-cache", "dpkg", "dpkg-query"}},
		{"ubuntu", "linux", "ID=ubuntu\nID_LIKE=debian", "debian", "apt-get", "APT_READ_ONLY", "PARTIALLY_SUPPORTED", []string{"apt-get", "apt-cache", "dpkg", "dpkg-query"}},
		{"mint", "linux", "ID=linuxmint\nID_LIKE=ubuntu debian", "debian", "apt-get", "DETECTION_ONLY", "DETECTION_ONLY", []string{"apt-get", "apt-cache", "dpkg", "dpkg-query"}},
		{"centos-stream", "linux", "NAME=\"CentOS Stream\"\nID=centos\nID_LIKE=\"rhel fedora\"", "rpm", "dnf", "DETECTION_ONLY", "DETECTION_ONLY", []string{"dnf", "rpm"}},
		{"centos-7", "linux", "ID=centos\nVERSION_ID=7", "rpm", "yum", "DETECTION_ONLY", "DETECTION_ONLY", []string{"yum", "rpm"}},
		{"almalinux", "linux", "ID=almalinux\nID_LIKE=\"rhel centos fedora\"", "rpm", "dnf", "DETECTION_ONLY", "DETECTION_ONLY", []string{"dnf", "rpm"}},
		{"rocky", "linux", "ID=rocky\nID_LIKE=\"rhel centos fedora\"", "rpm", "dnf", "DETECTION_ONLY", "DETECTION_ONLY", []string{"dnf", "rpm"}},
		{"fedora", "linux", "ID=fedora", "rpm", "dnf", "DETECTION_ONLY", "DETECTION_ONLY", []string{"dnf"}},
		{"opensuse", "linux", "ID=opensuse-tumbleweed", "suse", "zypper", "DETECTION_ONLY", "DETECTION_ONLY", []string{"zypper"}},
		{"arch", "linux", "ID=arch", "arch", "pacman", "DETECTION_ONLY", "DETECTION_ONLY", []string{"pacman"}},
		{"alpine", "linux", "ID=alpine", "alpine", "apk", "DETECTION_ONLY", "DETECTION_ONLY", []string{"apk"}},
		{"nixos", "linux", "ID=nixos", "nix", "nix", "DETECTION_ONLY", "DETECTION_ONLY", []string{"nix"}},
		{"unknown-linux", "linux", "ID=future-distro", "unknown", "unknown", "DETECTION_ONLY", "DETECTION_ONLY", nil},
		{"windows", "windows", "", "windows", "vendor-managed", "DETECTION_ONLY", "DETECTION_ONLY", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(cmd string) bool {
				for _, installed := range tc.available {
					if installed == cmd {
						return true
					}
				}
				return false
			}
			got := Describe(tc.goos, tc.release, lookup)
			if got.Family != tc.family || got.PackageManager != tc.manager || got.UpdatePlanning != tc.planning || got.Status != tc.status {
				t.Fatalf("got %+v, want family=%s manager=%s planning=%s status=%s", got, tc.family, tc.manager, tc.planning, tc.status)
			}
			if got.Distribution == "" || len(got.Limitations) == 0 {
				t.Fatalf("incomplete report: %+v", got)
			}
		})
	}
}

func TestDescribeRefusesAPTWithoutRequiredTools(t *testing.T) {
	got := Describe("linux", "ID=debian", func(name string) bool { return name == "apt-get" })
	if got.UpdatePlanning != "DETECTION_ONLY" || !strings.Contains(strings.Join(got.Limitations, " "), "required APT utilities") {
		t.Fatalf("accepted incomplete APT toolchain: %+v", got)
	}
}

func TestWindowsServerClassificationFailsClosed(t *testing.T) {
	base := Describe("windows", "", func(string) bool { return false })
	cases := []struct {
		name, productType, distribution string
	}{
		{"server", "ServerNT", "windows-server"},
		{"domain-controller", "LanmanNT", "windows-server-domain-controller"},
		{"desktop", "WinNT", "windows-client"},
		{"missing", "", "windows-unknown"},
		{"unrecognized", "AnotherType", "windows-unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := withWindowsProductType(base, tc.productType)
			if got.Distribution != tc.distribution || got.Status != "DETECTION_ONLY" || got.UpdatePlanning != "DETECTION_ONLY" {
				t.Fatalf("unsafe Windows support classification: %+v", got)
			}
			if len(got.Limitations) <= len(base.Limitations) {
				t.Fatalf("missing Windows-specific limitations: %+v", got)
			}
		})
	}
}
