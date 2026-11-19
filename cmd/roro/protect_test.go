package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/timeomy/roro/internal/config"
)

func TestEverydayConfigLoads(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), ".roro", "roro.yaml")
	created, err := ensureHome(cfgPath)
	if err != nil || !created {
		t.Fatalf("ensureHome = %v, %v", created, err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Pinning.OnChange != config.PinAlert || len(cfg.Matchers) != 7 {
		t.Errorf("pinning = %q, matchers = %d", cfg.Pinning.OnChange, len(cfg.Matchers))
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(filepath.Dir(cfgPath)); info.Mode().Perm() != 0o700 {
			t.Errorf("~/.roro mode = %v", info.Mode().Perm())
		}
	}
	// A second run leaves an existing setup alone.
	if created, err := ensureHome(cfgPath); err != nil || created {
		t.Errorf("second ensureHome = %v, %v", created, err)
	}
}

func TestReplaceFileRefusesWhenTheFileChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := os.WriteFile(path, []byte("now"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(path, []byte("earlier"), []byte("new")); !errors.Is(err, errChanged) {
		t.Fatalf("err = %v, want errChanged", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "now" {
		t.Errorf("file = %q", got)
	}
	if err := replaceFile(path, []byte("now"), []byte("new")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != "new" {
		t.Errorf("file = %q", got)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".roro-tmp-*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o640 {
			t.Errorf("mode = %v", info.Mode().Perm())
		}
	}
}

func TestReplaceFileKeepsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need extra rights on Windows")
	}
	dir := t.TempDir()
	real, link := filepath.Join(dir, "dotfiles.json"), filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(real, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(link, []byte("a"), []byte("b")); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Lstat(link); info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a regular file")
	}
	if got, _ := os.ReadFile(real); string(got) != "b" {
		t.Errorf("target = %q", got)
	}
}
