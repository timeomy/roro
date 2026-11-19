package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/timeomy/roro/internal/audit"
	"github.com/timeomy/roro/internal/clients"
	"github.com/timeomy/roro/policies"
)

// everydayMatchers replaces the starter matcher list in the config that
// `roro protect` writes. Each name is used by policies/examples/everyday.cedar.
const everydayMatchers = `matchers:
  - name: aws_access_key
    regex: '\b(AKIA|ASIA)[0-9A-Z]{16}\b'
  - name: private_key_block
    regex: '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  - name: github_token
    regex: '\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b'
  - name: api_secret_key
    regex: '(^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{32,}'
  - name: google_api_key
    regex: '\bAIza[0-9A-Za-z_-]{35}\b'
  - name: slack_token
    regex: '\bxox[abprs]-[A-Za-z0-9-]{10,}'
  - name: stripe_live_key
    regex: '\b[sr]k_live_[A-Za-z0-9]{20,}\b'
`

const starterMatchers = `matchers:
  - name: aws_access_key
    regex: '\b(AKIA|ASIA)[0-9A-Z]{16}\b'
  - name: private_key_block
    regex: '-----BEGIN [A-Z ]*PRIVATE KEY-----'
`

// everydayConfig is the roro.yaml for the home setup: state under
// ~/.roro/state, the everyday matchers, and tool changes logged instead of
// blocked so an updated server does not silently lose its tools.
func everydayConfig() (string, error) {
	cfg := fmt.Sprintf(configTemplate, "my-agent")
	for old, repl := range map[string]string{
		"state_dir: .roro\n":    "state_dir: state\n",
		"on_change: block\n":    "on_change: alert\n",
		starterMatchers:         everydayMatchers,
		"- policies/roro.cedar": "- policies/everyday.cedar",
	} {
		if !strings.Contains(cfg, old) {
			return "", fmt.Errorf("internal error: config template no longer contains %q", old)
		}
		cfg = strings.Replace(cfg, old, repl, 1)
	}
	return cfg, nil
}

// ensureHome creates ~/.roro (config, everyday policy, signing key) when it
// does not exist yet. An existing setup is left exactly as it is.
func ensureHome(cfgPath string) (created bool, err error) {
	if _, err := os.Stat(cfgPath); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	dir := filepath.Dir(cfgPath)
	polPath := filepath.Join(dir, "policies", "everyday.cedar")
	keyPath := filepath.Join(dir, "state", "audit-signing.key")
	cfg, err := everydayConfig()
	if err != nil {
		return false, err
	}
	for _, d := range []string{dir, filepath.Dir(polPath), filepath.Dir(keyPath)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return false, err
		}
	}
	// The folder holds the audit log and its signing key: owner only.
	if err := os.Chmod(dir, 0o700); err != nil {
		return false, err
	}
	if err := os.WriteFile(polPath, []byte(policies.Everyday), 0o644); err != nil {
		return false, err
	}
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		if _, err := audit.GenerateKey(keyPath); err != nil {
			return false, err
		}
	}
	// The config is written last: its presence means the setup is complete.
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// clientPlan is the outcome of looking at one client's configuration file.
type clientPlan struct {
	loc     clients.Location
	before  []byte
	after   []byte
	results []clients.Result
	err     error
}

func (p clientPlan) changed() bool { return p.err == nil && string(p.before) != string(p.after) }

func (p clientPlan) count(s clients.Status) int {
	n := 0
	for _, r := range p.results {
		if r.Status == s {
			n++
		}
	}
	return n
}

// planClients reads every supported client's configuration and works out
// the edit. Clients that are not installed are left out.
func planClients(home string, edit func(clients.Location, []byte) ([]byte, []clients.Result, error)) []clientPlan {
	var plans []clientPlan
	for _, loc := range clients.Locations(home, runtime.GOOS, os.Getenv("APPDATA")) {
		data, err := os.ReadFile(loc.Path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		p := clientPlan{loc: loc, before: data, err: err}
		if err == nil {
			p.after, p.results, p.err = edit(loc, data)
		}
		if p.err != nil || len(p.results) > 0 {
			plans = append(plans, p)
		}
	}
	return plans
}

var statusText = map[clients.Status]string{
	clients.Wrapped:            "will be protected",
	clients.AlreadyWrapped:     "already protected",
	clients.Unwrapped:          "will be restored",
	clients.NotWrapped:         "not protected, left alone",
	clients.SkippedRemote:      "skipped: it runs on the internet, not on this computer",
	clients.SkippedUnsupported: "skipped: written in a way Roro does not edit",
}

func printPlans(out io.Writer, plans []clientPlan) {
	for _, p := range plans {
		fmt.Fprintf(out, "\n  %s  (%s)\n", p.loc.Label, p.loc.Path)
		if p.err != nil {
			fmt.Fprintf(out, "    could not read this file, left alone: %s\n", clean(p.err.Error()))
			continue
		}
		for _, r := range p.results {
			name := clean(r.Server)
			if r.Scope != "" {
				name += " (in " + clean(r.Scope) + ")"
			}
			fmt.Fprintf(out, "    %-24s %s\n", name, statusText[r.Status])
		}
	}
	fmt.Fprintln(out)
}

// confirm asks a yes/no question. Anything but y or yes means no.
func confirm(in io.Reader, out io.Writer, question string) bool {
	fmt.Fprintf(out, "%s [y/N] ", question)
	line, _ := bufio.NewReader(in).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

// errChanged means a client rewrote its configuration after Roro read it.
var errChanged = errors.New("the file changed while Roro was working; run the command again")

// replaceFile swaps the contents of path from before to data. It writes
// through a temporary file so a crash cannot leave a half-written config,
// keeps the file's permissions, follows a symlink to the real file (so a
// dotfiles setup stays linked), and refuses if the file no longer holds
// before, so an edit the app made in the meantime is never lost.
func replaceFile(path string, before, data []byte) error {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".roro-tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, before) {
		return errChanged
	}
	return os.Rename(tmp.Name(), path)
}

// backupOnce keeps a copy of the file as it was before Roro first touched
// it. A later run never overwrites that copy.
func backupOnce(path string, original []byte) (string, error) {
	backup := path + ".before-roro"
	f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return backup, nil
	}
	if err != nil {
		return "", err
	}
	if _, err := f.Write(original); err != nil {
		_ = f.Close()
		return "", err
	}
	return backup, f.Close()
}

func applyPlans(out io.Writer, plans []clientPlan, backup bool) (changedLabels []string, failed bool) {
	for _, p := range plans {
		if !p.changed() {
			continue
		}
		if backup {
			if _, err := backupOnce(p.loc.Path, p.before); err != nil {
				fmt.Fprintf(out, "%s: could not save a copy, so nothing was changed: %v\n", p.loc.Label, err)
				failed = true
				continue
			}
		}
		if err := replaceFile(p.loc.Path, p.before, p.after); err != nil {
			fmt.Fprintf(out, "%s: could not update %s: %v\n", p.loc.Label, p.loc.Path, err)
			failed = true
			continue
		}
		changedLabels = append(changedLabels, p.loc.Label)
	}
	return changedLabels, failed
}

func total(plans []clientPlan, s clients.Status) int {
	n := 0
	for _, p := range plans {
		n += p.count(s)
	}
	return n
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func newProtectCmd() *cobra.Command {
	var yes, dryRun bool
	cmd := &cobra.Command{
		Use:   "protect",
		Short: "Protect the MCP servers your AI tools already use",
		Long: `protect finds the MCP servers set up in Claude Code, Claude Desktop, Cursor,
Windsurf, and Codex, and puts Roro in front of each one that runs on this
computer. You do not need to write any configuration.

After that, every tool call your AI tools make is logged, calls that carry
passwords or keys are blocked, and "roro kill" stops every agent at once.

Quit those apps first if you can: some of them rewrite their settings while
they run. It shows what it will change and asks before changing anything. A copy of
each file is kept next to it (NAME.before-roro), and "roro unprotect" puts
everything back. Run it again after you add a new MCP server.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProtect(cmd, yes, dryRun)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask before changing files")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would change and stop")
	return cmd
}

func runProtect(cmd *cobra.Command, yes, dryRun bool) error {
	out := cmd.OutOrStdout()
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot find your home folder: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find the roro program: %w", err)
	}
	// Keep the path as invoked (not symlink-resolved): package managers put a
	// stable link on PATH and move the real file on every upgrade.
	if self, err = filepath.Abs(self); err != nil {
		return fmt.Errorf("cannot find the roro program: %w", err)
	}
	cfgPath := filepath.Join(home, ".roro", "roro.yaml")
	w := clients.Wrapper{Roro: self, Config: cfgPath}

	plans := planClients(home, func(loc clients.Location, data []byte) ([]byte, []clients.Result, error) {
		if loc.Format == clients.FormatCodexTOML {
			return clients.ProtectCodexTOML(data, w)
		}
		return clients.ProtectJSON(data, loc.Client, w)
	})
	if len(plans) == 0 {
		fmt.Fprintln(out, "No MCP servers found in Claude Code, Claude Desktop, Cursor, Windsurf, or Codex.")
		fmt.Fprintln(out, "Add an MCP server to one of them, then run `roro protect` again.")
		return nil
	}
	fmt.Fprintln(out, "Roro found these MCP servers:")
	printPlans(out, plans)

	todo := total(plans, clients.Wrapped)
	if todo == 0 {
		fmt.Fprintln(out, "Nothing to change.")
		return nil
	}
	fmt.Fprintf(out, "Roro will put itself in front of %s. A copy of each file is kept next to it.\n", plural(todo, "server"))
	if dryRun {
		fmt.Fprintln(out, "Dry run: nothing was changed.")
		return nil
	}
	if !yes && !confirm(cmd.InOrStdin(), out, "Continue?") {
		fmt.Fprintln(out, "Nothing was changed.")
		return nil
	}
	if _, err := ensureHome(cfgPath); err != nil {
		return fmt.Errorf("could not set up %s: %w", filepath.Dir(cfgPath), err)
	}
	changed, failed := applyPlans(out, plans, true)
	if len(changed) > 0 {
		fmt.Fprintf(out, "\nDone. Restart %s so the change takes effect.\n\n", strings.Join(changed, ", "))
		fmt.Fprintln(out, "  roro logs        see what your AI tools did")
		fmt.Fprintln(out, "  roro kill        stop every agent right now")
		fmt.Fprintln(out, "  roro unprotect   undo this")
	}
	if failed {
		return errors.New("some files could not be updated; see above")
	}
	return nil
}

func newUnprotectCmd() *cobra.Command {
	var yes, dryRun bool
	cmd := &cobra.Command{
		Use:   "unprotect",
		Short: "Undo `roro protect`",
		Long: `unprotect takes Roro out from in front of your MCP servers, so each one runs
exactly as it did before. Your logs and settings in ~/.roro are kept.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUnprotect(cmd, yes, dryRun)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask before changing files")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would change and stop")
	return cmd
}

func runUnprotect(cmd *cobra.Command, yes, dryRun bool) error {
	out := cmd.OutOrStdout()
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot find your home folder: %w", err)
	}
	plans := planClients(home, func(loc clients.Location, data []byte) ([]byte, []clients.Result, error) {
		if loc.Format == clients.FormatCodexTOML {
			return clients.UnprotectCodexTOML(data)
		}
		return clients.UnprotectJSON(data)
	})
	todo := total(plans, clients.Unwrapped)
	if todo == 0 {
		fmt.Fprintln(out, "Nothing is protected by Roro, so there is nothing to undo.")
		return nil
	}
	fmt.Fprintln(out, "Roro is in front of these MCP servers:")
	printPlans(out, plans)
	fmt.Fprintf(out, "Roro will restore %s to how it ran before.\n", plural(todo, "server"))
	if dryRun {
		fmt.Fprintln(out, "Dry run: nothing was changed.")
		return nil
	}
	if !yes && !confirm(cmd.InOrStdin(), out, "Continue?") {
		fmt.Fprintln(out, "Nothing was changed.")
		return nil
	}
	changed, failed := applyPlans(out, plans, false)
	if len(changed) > 0 {
		fmt.Fprintf(out, "\nDone. Restart %s so the change takes effect.\n", strings.Join(changed, ", "))
	}
	if failed {
		return errors.New("some files could not be updated; see above")
	}
	return nil
}
