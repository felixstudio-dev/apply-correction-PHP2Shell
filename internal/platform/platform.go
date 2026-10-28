// Package platform describes operating-system families without modifying them.
package platform

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Info describes discovery and package-update planning capability separately.
// DETECTION_ONLY is not a claim of tested installation, mitigation, or rollback.
type Info struct {
	OperatingSystem string   `json:"operating_system"`
	Distribution    string   `json:"distribution"`
	Version         string   `json:"distribution_version,omitempty"`
	Family          string   `json:"family"`
	PackageManager  string   `json:"package_manager"`
	UpdatePlanning  string   `json:"update_planning"`
	Status          string   `json:"status"`
	Limitations     []string `json:"limitations"`
}

// Detect reads only local OS metadata and checks whether package-manager
// commands can be resolved; it never calls a package manager.
func Detect() Info {
	var release string
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			release = string(data)
		}
	}
	p := Describe(runtime.GOOS, release, func(command string) bool {
		_, err := exec.LookPath(command)
		return err == nil
	})
	if runtime.GOOS == "windows" {
		p = withWindowsProductType(p, readWindowsProductType())
	}
	return p
}

// Describe is deterministic so detection can be verified without each OS.
func Describe(goos, osRelease string, commandAvailable func(string) bool) Info {
	p := Info{
		OperatingSystem: goos,
		Distribution:    "unknown",
		Family:          "unknown",
		PackageManager:  "unknown",
		UpdatePlanning:  "DETECTION_ONLY",
		Status:          "DETECTION_ONLY",
		Limitations: []string{
			"A detected PHP CLI does not establish the active web server runtime or a vendor security backport.",
			"Automatic core PHP package upgrades and service restarts are not implemented for this platform.",
		},
	}
	if goos == "windows" {
		p.Distribution, p.Family, p.PackageManager = "windows-unknown", "windows", "vendor-managed"
		p.Limitations = append(p.Limitations, "Windows installation type cannot be inferred from GOOS; Windows Server and IIS/FastCGI require independent verification.")
		return p
	}
	if goos != "linux" {
		p.Status = "UNSUPPORTED"
		p.Limitations = append(p.Limitations, "Only Linux and Windows are currently targeted.")
		return p
	}
	metadata := parseOSRelease(osRelease)
	if id := metadata["ID"]; id != "" {
		p.Distribution = strings.ToLower(id)
	}
	p.Version = metadata["VERSION_ID"]
	likes := strings.Fields(strings.ToLower(metadata["ID_LIKE"]))
	ids := append([]string{p.Distribution}, likes...)
	contains := func(values ...string) bool {
		for _, id := range ids {
			for _, value := range values {
				if id == value {
					return true
				}
			}
		}
		return false
	}
	var commands []string
	switch {
	case contains("debian", "ubuntu", "linuxmint", "pop", "kali", "elementary", "zorin", "raspbian", "devuan"):
		p.Family, commands = "debian", []string{"apt-get"}
	case contains("rhel", "centos", "fedora", "almalinux", "rocky", "ol", "amzn", "cloudlinux", "anolis", "opencloudos"):
		p.Family, commands = "rpm", []string{"dnf", "yum"}
	case contains("suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles"):
		p.Family, commands = "suse", []string{"zypper"}
	case contains("arch", "manjaro", "endeavouros", "garuda"):
		p.Family, commands = "arch", []string{"pacman"}
	case contains("alpine"):
		p.Family, commands = "alpine", []string{"apk"}
	case contains("gentoo"):
		p.Family, commands = "gentoo", []string{"emerge"}
	case contains("nixos"):
		p.Family, commands = "nix", []string{"nix"}
	case contains("void"):
		p.Family, commands = "void", []string{"xbps-install"}
	case contains("clear-linux-os"):
		p.Family, commands = "clear-linux", []string{"swupd"}
	case contains("slackware"):
		p.Family, commands = "slackware", []string{"slackpkg"}
	default:
		// Do not guess that an unrecognized distribution follows an APT or RPM
		// upgrade contract just because a command is installed.
		p.Limitations = append(p.Limitations, "Unknown Linux distribution: select the vendor-supported security update procedure.")
	}
	for _, command := range commands {
		if commandAvailable(command) {
			p.PackageManager = command
			break
		}
	}
	if (p.Distribution == "debian" || p.Distribution == "ubuntu") &&
		commandAvailable("apt-get") && commandAvailable("apt-cache") &&
		commandAvailable("dpkg") && commandAvailable("dpkg-query") {
		p.UpdatePlanning = "APT_READ_ONLY"
		p.Status = "PARTIALLY_SUPPORTED"
	} else if p.Distribution == "debian" || p.Distribution == "ubuntu" {
		p.Limitations = append(p.Limitations, "The required APT utilities are unavailable; package planning is disabled.")
	}
	return p
}

// withWindowsProductType maps the OS-reported installation type, not a guessed
// edition or a PHP runtime. Registry lookup failures remain detection-only.
func withWindowsProductType(p Info, productType string) Info {
	switch strings.ToLower(strings.TrimSpace(productType)) {
	case "servernt":
		p.Distribution = "windows-server"
		p.Limitations = append(p.Limitations, "Windows Server PHP/IIS FastCGI worker bindings, extensions, service state and patch levels have not been physically verified.")
	case "lanmannt":
		p.Distribution = "windows-server-domain-controller"
		p.Limitations = append(p.Limitations, "Domain controllers require independent security and change-control review before any server PHP modification.")
	case "winnt":
		p.Distribution = "windows-client"
		p.Limitations = append(p.Limitations, "Windows client Apache, IIS/FastCGI, and PHP runtime bindings are not automatically verified.")
	default:
		p.Limitations = append(p.Limitations, "Could not verify Windows installation type from the operating system; no server support inference is allowed.")
	}
	return p
}

func parseOSRelease(content string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return values
}
