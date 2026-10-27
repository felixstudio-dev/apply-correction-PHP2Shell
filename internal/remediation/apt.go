// Package remediation prepares narrowly scoped security upgrade plans.
// Planning executes read-only package-manager commands. No package install is performed.
package remediation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/felixstudio-dev/apply-correction-PHP2Shell/internal/assessment"
)

// Runner separates the planner from platform-specific package-manager processes.
type Runner interface {
	Run(ctx context.Context, executable string, args ...string) (string, error)
}

type CommandRunner struct{}

func (CommandRunner) Run(ctx context.Context, executable string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, executable, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("package metadata query %s failed: %w", executable, err)
	}
	return string(out), nil
}

type Package struct {
	Name      string `json:"name"`
	Installed string `json:"installed"`
	Candidate string `json:"candidate"`
	Origin    string `json:"origin"`
	FixStatus string `json:"fix_status"`
}

type Plan struct {
	Status          string    `json:"status"`
	Distribution    string    `json:"distribution"`
	PHPVersion      string    `json:"php_version"`
	RequiredVersion string    `json:"upstream_fixed_floor,omitempty"`
	Packages        []Package `json:"packages"`
	PreviewCommand  []string  `json:"preview_command,omitempty"`
	Reasons         []string  `json:"reasons"`
	Limitations     []string  `json:"limitations"`
}

var installedPackage = regexp.MustCompile(`^(php[0-9]+\.[0-9]+(?:-[a-z0-9.+-]+)?|libapache2-mod-php[0-9]+\.[0-9]+)(?::[a-z0-9]+)?$`)
var versionFragment = regexp.MustCompile(`(?:^|:)([0-9]+\.[0-9]+\.[0-9]+)(?:[~+._-]|$)`)

func ReadDistribution() (string, error) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "ID=") {
			id := strings.Trim(strings.TrimPrefix(line, "ID="), "\"'")
			return strings.ToLower(id), nil
		}
	}
	return "", errors.New("distribution ID is unavailable")
}

// BoundToAPT proves the exact selected PHP CLI is owned by its native package.
// An unrelated or shadow executable must not be treated as an apt-managed runtime.
func BoundToAPT(ctx context.Context, phpPath, phpVersion string, runner Runner) (bool, error) {
	v, err := assessment.ParseVersion(phpVersion)
	if err != nil {
		return false, err
	}
	resolved, err := filepath.EvalSymlinks(phpPath)
	if err != nil {
		return false, err
	}
	if resolved != fmt.Sprintf("/usr/bin/php%d.%d", v.Major, v.Minor) {
		return false, nil
	}
	result, err := runner.Run(ctx, "/usr/bin/dpkg-query", "-S", resolved)
	if err != nil {
		return false, err
	}
	needle := fmt.Sprintf("php%d.%d-cli", v.Major, v.Minor)
	for _, line := range strings.Split(result, "\n") {
		fields := strings.SplitN(line, ": ", 2)
		if len(fields) == 2 && strings.Split(fields[0], ":")[0] == needle && strings.TrimSpace(fields[1]) == resolved {
			return true, nil
		}
	}
	return false, nil
}

// PlanAPT is a fail-closed, read-only planner for native apt-managed PHP packages.
// A vendor security backport cannot be proven by a PHP version string.
func PlanAPT(ctx context.Context, distribution, phpVersion string, runner Runner) (Plan, error) {
	p := Plan{Distribution: distribution, PHPVersion: phpVersion, Status: "UNSUPPORTED", Packages: []Package{}, Reasons: []string{}, Limitations: []string{
		"No packages are changed by planning; a separate authorized vendor upgrade is required.",
		"A package update may restart services, run maintainer scripts, or require a different recovery procedure.",
		"The plan does not verify active PHP-FPM, Apache, container, or IIS workers and does not prove a vendor security backport.",
	}}
	if distribution != "ubuntu" && distribution != "debian" {
		p.Reasons = append(p.Reasons, "Only the native Ubuntu and Debian apt inventory is supported")
		return p, nil
	}
	v, err := assessment.ParseVersion(phpVersion)
	if err != nil {
		return p, fmt.Errorf("cannot plan an update for an invalid PHP version: %w", err)
	}
	min, known := assessment.MinimumFixed(v.Major, v.Minor)
	if !known {
		p.Reasons = append(p.Reasons, "The running PHP branch has no verified upstream fix floor in the current catalog")
		return p, nil
	}
	branch := fmt.Sprintf("%d.%d", v.Major, v.Minor)
	p.RequiredVersion = fmt.Sprintf("%s.%d", branch, min)
	output, err := runner.Run(ctx, "/usr/bin/dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\n", "php*", "libapache2-mod-php*")
	if err != nil {
		return p, err
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) != 3 || !strings.HasPrefix(fields[0], "ii") {
			continue
		}
		if !installedPackage.MatchString(fields[1]) {
			continue
		}
		name := fields[1]
		base := strings.Split(name, ":")[0]
		if !strings.HasPrefix(base, "php"+branch+"-") && base != "php"+branch && base != "libapache2-mod-php"+branch {
			continue
		}
		p.Packages = append(p.Packages, Package{Name: name, Installed: fields[2]})
	}
	sort.Slice(p.Packages, func(i, j int) bool { return p.Packages[i].Name < p.Packages[j].Name })
	if !containsCLI(p.Packages, branch) {
		p.Status = "PACKAGE_PROVENANCE_UNVERIFIED"
		p.Reasons = append(p.Reasons, "The selected PHP branch has no installed matching php"+branch+"-cli apt package")
		return p, nil
	}
	allFixed := true
	allTrusted := true
	upgradeAvailable := false
	upgrades := make(map[string]bool)
	for i := range p.Packages {
		pkg := &p.Packages[i]
		policy, queryErr := runner.Run(ctx, "/usr/bin/apt-cache", "policy", pkg.Name)
		if queryErr != nil {
			return p, fmt.Errorf("candidate lookup for %s: %w", pkg.Name, queryErr)
		}
		candidate := candidateFromPolicy(policy)
		pkg.Candidate = candidate
		if candidate == "" || candidate == "(none)" {
			pkg.FixStatus = "NO_CANDIDATE"
			allFixed = false
			allTrusted = false
			p.Reasons = append(p.Reasons, "No candidate version for "+pkg.Name)
			continue
		}
		origin := candidateOrigin(policy, candidate)
		pkg.Origin = origin
		if origin != expectedOrigin(distribution) {
			allTrusted = false
			p.Reasons = append(p.Reasons, "Cannot establish an official distribution origin for "+pkg.Name)
		}
		currentVersion, currentKnown := upstreamVersion(pkg.Installed)
		futureVersion, futureKnown := upstreamVersion(pkg.Candidate)
		if !futureKnown || futureVersion.Major != v.Major || futureVersion.Minor != v.Minor || futureVersion.Patch < min {
			allFixed = false
			pkg.FixStatus = "VENDOR_ADVISORY_REQUIRED"
			p.Reasons = append(p.Reasons, "Candidate of "+pkg.Name+" does not independently prove the upstream PHP security fix; verify backports with the vendor")
		} else {
			pkg.FixStatus = "CANDIDATE_MEETS_UPSTREAM_FLOOR"
		}
		if currentKnown && futureKnown && (currentVersion.Major != futureVersion.Major || currentVersion.Minor != futureVersion.Minor) {
			allFixed = false
			pkg.FixStatus = "MAJOR_OR_MINOR_CHANGE_BLOCKED"
		}
		if pkg.Candidate != pkg.Installed {
			// Any failed ordering comparison is unsafe, including an older candidate
			// or a failure to execute dpkg. Equal versions need no comparison.
			if _, compareErr := runner.Run(ctx, "/usr/bin/dpkg", "--compare-versions", pkg.Candidate, "gt", pkg.Installed); compareErr != nil {
				allFixed = false
				p.Reasons = append(p.Reasons, "Could not prove package ordering for "+pkg.Name)
			} else {
				upgradeAvailable = true
				upgrades[pkg.Name] = true
			}
		}
	}
	if !allTrusted {
		p.Status = "PACKAGE_ORIGIN_REVIEW_REQUIRED"
		return p, nil
	}
	if !allFixed {
		p.Status = "VENDOR_ADVISORY_REQUIRED"
		return p, nil
	}
	if !upgradeAvailable {
		p.Status = "NO_NEWER_VERIFIED_PACKAGE"
		return p, nil
	}
	args := []string{"-s", "--only-upgrade", "--no-install-recommends", "install"}
	for _, pkg := range p.Packages {
		args = append(args, pkg.Name)
	}
	simulation, err := runner.Run(ctx, "/usr/bin/apt-get", args...)
	if err != nil {
		p.Status = "SIMULATION_FAILED"
		p.Reasons = append(p.Reasons, "APT upgrade simulation failed")
		return p, nil
	}
	allowed := make(map[string]Package)
	for _, pkg := range p.Packages {
		allowed[pkg.Name] = pkg
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(simulation, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "Remv" || fields[0] == "Purg" || fields[0] == "Inst" && (len(fields) < 2 || !hasPackage(allowed, fields[1])) {
			p.Status = "DEPENDENCY_CHANGES_REQUIRE_REVIEW"
			p.Reasons = append(p.Reasons, "APT simulation would remove or install packages outside the selected PHP branch")
			return p, nil
		}
		switch fields[0] {
		case "Inst":
			pkg := allowed[fields[1]]
			// apt-get -s reports: Inst name [installed] (candidate origin...)
			// Require exact installed and candidate versions, not just package names.
			if !upgrades[fields[1]] || len(fields) < 5 ||
				fields[2] != "["+pkg.Installed+"]" ||
				fields[3] != "("+pkg.Candidate ||
				!strings.HasSuffix(fields[len(fields)-1], ")") {
				p.Status = "SIMULATION_MISMATCH"
				p.Reasons = append(p.Reasons, "APT simulation contains a duplicate, malformed, or inconsistent package upgrade")
				return p, nil
			}
			delete(upgrades, fields[1])
			seen[fields[1]] = true
		case "Conf":
			if len(fields) < 4 || !seen[fields[1]] ||
				fields[2] != "("+allowed[fields[1]].Candidate ||
				!strings.HasSuffix(fields[len(fields)-1], ")") {
				p.Status = "SIMULATION_MISMATCH"
				p.Reasons = append(p.Reasons, "APT simulation would configure an unplanned package or version")
				return p, nil
			}
		case "Keep":
			p.Status = "SIMULATION_MISMATCH"
			p.Reasons = append(p.Reasons, "APT simulation contains a held package")
			return p, nil
		}
	}
	if len(upgrades) != 0 {
		p.Status = "SIMULATION_INCOMPLETE"
		p.Reasons = append(p.Reasons, "APT simulation did not show every expected installed-package upgrade")
		return p, nil
	}
	p.Status = "ELIGIBLE_FOR_ADMIN_REVIEW"
	p.PreviewCommand = append([]string{"sudo", "/usr/bin/apt-get", "--only-upgrade", "--no-install-recommends", "install"}, packageNames(p.Packages)...)
	p.Reasons = append(p.Reasons, "Candidate metadata points to official repository hosts and upstream patch floors; independently confirm signed provenance, service impact and backups before execution")
	// Repository host and version are only preflight indicators; signed package
	// provenance and effective web-worker patch status remain unverified.
	return p, nil
}

func hasPackage(packages map[string]Package, name string) bool {
	_, found := packages[name]
	return found
}

func containsCLI(packages []Package, branch string) bool {
	for _, pkg := range packages {
		if strings.Split(pkg.Name, ":")[0] == "php"+branch+"-cli" {
			return true
		}
	}
	return false
}

func packageNames(pkgs []Package) []string {
	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	return names
}

func candidateFromPolicy(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Candidate:") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "Candidate:"))
		}
	}
	return ""
}

func expectedOrigin(distro string) string {
	if distro == "ubuntu" {
		return "Ubuntu"
	}
	if distro == "debian" {
		return "Debian"
	}
	return ""
}

func candidateOrigin(text, candidate string) string {
	active := false
	origin := ""
	foreignSource := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "*** ") {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "*** "))
		}
		fields := strings.Fields(trimmed)
		// A candidate's version-table entry has a version and priority, not a source path.
		if len(fields) >= 2 && fields[0] == candidate && isNumber(fields[1]) {
			active = true
			continue
		}
		if active && len(fields) >= 2 && isNumber(fields[1]) && fields[0] != candidate && versionFragment.MatchString(fields[0]) {
			active = false
		}
		if active {
			// Release labels alone can be forged by a custom apt repository.
			// All candidate sources must come from accepted official hosts.
			if len(fields) >= 2 && isNumber(fields[0]) && (strings.HasPrefix(fields[1], "http") || strings.HasPrefix(fields[1], "file:")) {
				source := fields[1]
				switch {
				case officialAPTSource(source, "archive.ubuntu.com", "/ubuntu"), officialAPTSource(source, "security.ubuntu.com", "/ubuntu"):
					if origin != "" && origin != "Ubuntu" {
						foreignSource = true
					}
					origin = "Ubuntu"
				case officialAPTSource(source, "deb.debian.org", "/debian"), officialAPTSource(source, "security.debian.org", "/debian-security"), officialAPTSource(source, "deb.debian.org", "/debian-security"):
					if origin != "" && origin != "Debian" {
						foreignSource = true
					}
					origin = "Debian"
				default:
					foreignSource = true
				}
			}
		}
	}
	if foreignSource || origin == "" {
		return "UNVERIFIED"
	}
	return origin
}

func officialAPTSource(source, host, path string) bool {
	return source == "https://"+host+path || source == "http://"+host+path
}

func isNumber(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func upstreamVersion(pkgVersion string) (assessment.Version, bool) {
	matches := versionFragment.FindStringSubmatch(pkgVersion)
	if len(matches) < 2 {
		return assessment.Version{}, false
	}
	v, err := assessment.ParseVersion(matches[1])
	return v, err == nil
}
