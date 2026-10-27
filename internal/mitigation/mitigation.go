package mitigation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const maxINI = 16 << 20

type Record struct {
	ID           string `json:"id"`
	Created      string `json:"created_utc"`
	Target       string `json:"target"`
	OriginalHash string `json:"original_sha256"`
	AppliedHash  string `json:"applied_sha256"`
	Backup       string `json:"backup"`
	Mode         uint32 `json:"mode"`
	Action       string `json:"action"`
	CLIValidated bool   `json:"cli_validated"`
	RolledBack   bool   `json:"rolled_back"`
}

var validID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func DefaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".php2shell-fix"), nil
}

func Hash(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

func checkNoLinks(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for p := abs; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink/junction in writable path: %s", p)
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}

func readINI(path string) ([]byte, os.FileMode, error) {
	if err := checkNoLinks(path); err != nil {
		return nil, 0, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	if !st.Mode().IsRegular() {
		return nil, 0, errors.New("configuration is not a regular file")
	}
	if st.Size() > maxINI {
		return nil, 0, errors.New("configuration exceeds 16 MiB limit")
	}
	b, err := os.ReadFile(path)
	if err == nil && strings.ContainsRune(string(b), '\x00') {
		return nil, 0, errors.New("configuration contains NUL bytes; refusing to edit")
	}
	return b, st.Mode().Perm(), err
}

func PatchUploadProgress(original []byte) ([]byte, bool) {
	// An explicit final directive takes precedence over earlier php.ini directives.
	// Read-only scan must determine whether a system's effective setting already disables it.
	for _, line := range strings.Split(string(original), "\n") {
		if strings.TrimSpace(strings.ToLower(line)) == "; php2shell-fix: cve-2026-115560 mitigation" {
			return original, false
		}
	}
	newline := "\n"
	if strings.Contains(string(original), "\r\n") {
		newline = "\r\n"
	}
	end := []byte{}
	if len(original) > 0 && original[len(original)-1] != '\n' {
		end = append(end, []byte(newline)...)
	}
	patched := append(append(append([]byte{}, original...), end...), []byte("; php2shell-fix: CVE-2026-115560 mitigation"+newline+"session.upload_progress.enabled=Off"+newline)...)
	return patched, true
}

func ensureStateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	if err := checkNoLinks(path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0700); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		current, err := user.Current()
		if err != nil {
			return err
		}
		if !strings.HasPrefix(current.Uid, "S-") {
			return errors.New("cannot resolve Windows SID for private backup ACL")
		}
		cmd := exec.Command("icacls", path, "/inheritance:r", "/grant:r", "*"+current.Uid+":(OI)(CI)F")
		if b, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to secure backup ACL: %v: %s", err, strings.TrimSpace(string(b)))
		}
	}
	return nil
}

func lockDir(path string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(path, ".lock"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("another operation or an interrupted operation holds the lock: %w", err)
	}
	f.Close()
	return func() { _ = os.Remove(filepath.Join(path, ".lock")) }, nil
}

func saveNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}

func atomicReplace(path string, data []byte, mode os.FileMode) error {
	if err := checkNoLinks(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".php2shell-fix-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return replaceFile(tmp, path)
}

// Apply changes only an explicitly selected php.ini. The caller verifies PHP CLI's loaded path.
// A full PHP2Shell fix requires an official PHP upgrade; this is a separate conditional mitigation.
func Apply(target, stateDir string, validate func() error) (Record, error) {
	if err := ensureStateDir(stateDir); err != nil {
		return Record{}, err
	}
	unlock, err := lockDir(stateDir)
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	target, err = filepath.Abs(target)
	if err != nil {
		return Record{}, err
	}
	before, mode, err := readINI(target)
	if err != nil {
		return Record{}, err
	}
	after, changed := PatchUploadProgress(before)
	if !changed {
		return Record{}, errors.New("previous mitigation marker found; verify effective configuration before retrying")
	}
	var raw [16]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return Record{}, err
	}
	id := hex.EncodeToString(raw[:])
	backup := filepath.Join(stateDir, id+".ini.bak")
	record := Record{ID: id, Created: time.Now().UTC().Format(time.RFC3339), Target: target, OriginalHash: Hash(before), AppliedHash: Hash(after), Backup: backup, Mode: uint32(mode), Action: "disable session.upload_progress for CVE-2026-115560"}
	if err = saveNew(backup, before); err != nil {
		return Record{}, err
	}
	if err = saveNew(filepath.Join(stateDir, id+".json"), mustJSON(record)); err != nil {
		return Record{}, err
	}
	// Fail closed if another administrator changed the file while preparing recovery data.
	latest, _, err := readINI(target)
	if err != nil {
		return Record{}, err
	}
	if Hash(latest) != record.OriginalHash {
		return Record{}, errors.New("configuration changed during backup; update aborted")
	}
	if err = atomicReplace(target, after, mode); err != nil {
		return Record{}, err
	}
	if validate != nil {
		if verifyErr := validate(); verifyErr != nil {
			if current, _, readErr := readINI(target); readErr == nil && Hash(current) == record.AppliedHash {
				_ = atomicReplace(target, before, mode)
			}
			return Record{}, fmt.Errorf("CLI post-change verification failed; attempted safe restore: %w", verifyErr)
		}
		record.CLIValidated = true
	}
	if err = writeRecord(stateDir, record); err != nil {
		return record, fmt.Errorf("mitigation applied but record update failed: %w", err)
	}
	return record, nil
}

func mustJSON(v any) []byte { b, _ := json.MarshalIndent(v, "", "  "); return append(b, '\n') }

func writeRecord(stateDir string, r Record) error {
	return atomicReplace(filepath.Join(stateDir, r.ID+".json"), mustJSON(r), 0600)
}

func Rollback(id, stateDir string) (Record, error) {
	if !validID.MatchString(id) {
		return Record{}, errors.New("invalid backup ID")
	}
	if err := checkNoLinks(stateDir); err != nil {
		return Record{}, err
	}
	unlock, err := lockDir(stateDir)
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	raw, err := os.ReadFile(filepath.Join(stateDir, id+".json"))
	if err != nil {
		return Record{}, err
	}
	var r Record
	if err = json.Unmarshal(raw, &r); err != nil {
		return Record{}, err
	}
	if r.ID != id || r.Backup != filepath.Join(stateDir, id+".ini.bak") {
		return Record{}, errors.New("record integrity validation failed")
	}
	backup, _, err := readINI(r.Backup)
	if err != nil {
		return Record{}, err
	}
	if Hash(backup) != r.OriginalHash {
		return Record{}, errors.New("backup integrity check failed")
	}
	current, _, err := readINI(r.Target)
	if err != nil {
		return Record{}, err
	}
	if Hash(current) == r.OriginalHash {
		r.RolledBack = true
		_ = writeRecord(stateDir, r)
		return r, nil
	}
	if Hash(current) != r.AppliedHash {
		return Record{}, errors.New("configuration changed after mitigation; manual review required")
	}
	if err = atomicReplace(r.Target, backup, os.FileMode(r.Mode)); err != nil {
		return Record{}, err
	}
	r.RolledBack = true
	return r, writeRecord(stateDir, r)
}

// RequireMode refuses world/group-readable state directories on POSIX systems.
func RequireMode(stateDir string) error {
	if err := checkNoLinks(stateDir); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(stateDir)
		if err != nil {
			return err
		}
		if st.Mode().Perm()&0077 != 0 {
			return errors.New("backup directory permissions are too broad")
		}
	}
	return nil
}

func ReadRecord(id, stateDir string) (Record, error) {
	if !validID.MatchString(id) {
		return Record{}, errors.New("invalid backup ID")
	}
	if err := RequireMode(stateDir); err != nil {
		return Record{}, err
	}
	f, err := os.Open(filepath.Join(stateDir, id+".json"))
	if err != nil {
		return Record{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return Record{}, err
	}
	var r Record
	err = json.Unmarshal(data, &r)
	return r, err
}
