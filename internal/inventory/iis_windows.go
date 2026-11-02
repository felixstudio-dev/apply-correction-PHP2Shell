//go:build windows

package inventory

import (
	"os"
	"path/filepath"
)

// DetectIIS inspects a standard applicationHost.config with the current
// user's privileges. Custom paths, inherited external configuration and
// effective IIS worker state require independent validation.
func DetectIIS() *IISReport {
	result := &IISReport{
		Status:   "UNVERIFIED",
		Bindings: []IISBinding{},
		Limitations: []string{
			"IIS configuration entries do not prove the active FastCGI worker, runtime version, loaded php.ini, patch status, or site health.",
			"Only the standard global IIS configuration file is inspected; delegated config and custom installations require independent verification.",
		},
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		result.Limitations = append(result.Limitations, "Windows system root could not be resolved.")
		return result
	}
	path := filepath.Join(root, "System32", "inetsrv", "config", "applicationHost.config")
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			result.Status = "CONFIG_NOT_FOUND"
			result.Limitations = append(result.Limitations, "Standard IIS configuration was not found; this does not establish that IIS is disabled.")
		} else {
			result.Status = "UNREADABLE"
			result.Limitations = append(result.Limitations, "IIS configuration could not be read using the current process permissions.")
		}
		return result
	}
	defer file.Close()
	bindings, err := ParseIISFastCGI(file)
	if err != nil {
		result.Status = "INVALID_CONFIGURATION"
		result.Limitations = append(result.Limitations, "IIS configuration could not be safely parsed in the bounded inspection.")
		return result
	}
	result.Bindings = bindings
	result.Status = "NO_PHP_MAPPINGS_FOUND"
	if len(bindings) > 0 {
		result.Status = "CONFIGURED_ONLY"
	}
	return result
}
