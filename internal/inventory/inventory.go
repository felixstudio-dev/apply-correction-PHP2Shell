package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type PHP struct {
	Executable     string `json:"executable"`
	Version        string `json:"version,omitempty"`
	SAPI           string `json:"sapi,omitempty"`
	INI            string `json:"ini,omitempty"`
	UploadProgress string `json:"upload_progress,omitempty"`
	Provenance     string `json:"provenance"`
	Context        string `json:"context"`
	Error          string `json:"error,omitempty"`
}

func Candidates(explicit string) []string {
	if explicit != "" {
		return []string{explicit}
	}
	seen := make(map[string]bool)
	var paths []string
	add := func(p string) {
		if p == "" {
			return
		}
		p, err := filepath.Abs(p)
		if err != nil {
			return
		}
		if _, err := os.Stat(p); err != nil {
			return
		}
		key := strings.ToLower(p)
		if seen[key] {
			return
		}
		seen[key] = true
		paths = append(paths, p)
	}
	exe := "php"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		add(filepath.Join(dir, exe))
	}
	if runtime.GOOS == "linux" {
		for _, pattern := range []string{"/usr/bin/php", "/usr/bin/php[0-9]*", "/usr/local/bin/php", "/opt/remi/php*/root/usr/bin/php"} {
			matches, _ := filepath.Glob(pattern)
			for _, p := range matches {
				add(p)
			}
		}
	}
	if runtime.GOOS == "windows" {
		for _, pattern := range []string{`C:\php\php.exe`, `C:\Program Files\PHP\*\php.exe`, `C:\xampp\php\php.exe`} {
			matches, _ := filepath.Glob(pattern)
			for _, p := range matches {
				add(p)
			}
		}
	}
	sort.Strings(paths)
	return paths
}

// Inspect executes the local PHP CLI only; it never claims to identify live web workers.
func Inspect(path string) PHP {
	p := PHP{Executable: path, Provenance: "unknown", Context: "cli-only; web worker not verified"}
	abs, err := filepath.Abs(path)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.Executable = abs
	st, err := os.Stat(abs)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	if st.IsDir() {
		p.Error = "PHP executable is a directory"
		return p
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	script := `echo json_encode(['version'=>PHP_VERSION,'sapi'=>PHP_SAPI,'ini'=>php_ini_loaded_file() ?: '','progress'=>ini_get('session.upload_progress.enabled')]);`
	cmd := exec.CommandContext(ctx, abs, "-r", script)
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			p.Error = "PHP inspection timed out"
		} else {
			p.Error = fmt.Sprintf("PHP CLI inspection failed: %v", err)
		}
		return p
	}
	var values struct {
		Version  string `json:"version"`
		SAPI     string `json:"sapi"`
		INI      string `json:"ini"`
		Progress string `json:"progress"`
	}
	if err := json.Unmarshal(out, &values); err != nil {
		p.Error = "PHP inspection returned invalid JSON"
		return p
	}
	p.Version = values.Version
	p.SAPI = values.SAPI
	p.INI = values.INI
	p.UploadProgress = values.Progress
	return p
}
