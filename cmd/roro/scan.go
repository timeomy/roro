package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/timeomy/roro/internal/clients"
	"github.com/timeomy/roro/internal/scan"
)

// projectConfig is the per-project MCP file Claude Code and others read.
const projectConfig = ".mcp.json"

type scanFlags struct {
	json    bool
	failOn  string
	show    string
	files   []string
	noColor bool
}

// findingsError makes `roro scan` exit non-zero when it finds issues at or
// above --fail-on, without being reported as a failure to run.
type findingsError struct{ n int }

func (e findingsError) Error() string {
	return fmt.Sprintf("%s at or above the --fail-on level", plural(e.n, "finding"))
}

func newScanCmd() *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Check your MCP server setup for risky entries",
		Long: `Scan reads the MCP configuration of Claude Code, Claude Desktop, Cursor,
Windsurf, and Codex (and ./.mcp.json, if present) and reports risky server
entries: secrets written in the file, packages not pinned to a version, plain
HTTP servers, access to your whole disk or home folder, privileged containers,
and servers Roro does not protect.

It only reads files. It never starts a server or connects to one.

Exit status: 0 when nothing reaches --fail-on, 1 when something does or the
scan could not run.`,
		Example: `  roro scan
  roro scan --show info
  roro scan --file ./.mcp.json --fail-on medium
  roro scan --json > mcp-scan.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runScan(cmd.OutOrStdout(), f) },
	}
	cmd.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
	cmd.Flags().StringVar(&f.failOn, "fail-on", "high", "exit 1 on findings at or above: high, medium, low, info, or none")
	cmd.Flags().StringVar(&f.show, "show", "low", "list findings at or above: high, medium, low, or info")
	cmd.Flags().StringArrayVar(&f.files, "file", nil, "scan this config file instead of the usual places (repeatable; .toml is read as Codex)")
	cmd.Flags().BoolVar(&f.noColor, "no-color", false, "plain text output")
	return cmd
}

func runScan(out io.Writer, f *scanFlags) error {
	show, ok := scan.ParseSeverity(f.show)
	if !ok {
		return fmt.Errorf("invalid --show %q: use high, medium, low, or info", f.show)
	}
	failOn, fail := scan.ParseSeverity(f.failOn)
	if !fail && f.failOn != "none" {
		return fmt.Errorf("invalid --fail-on %q: use high, medium, low, info, or none", f.failOn)
	}
	home, _ := os.UserHomeDir()
	locs, err := scanLocations(home, f.files)
	if err != nil {
		return err
	}
	reports := scanAll(locs, scan.Context{Home: home})
	if len(reports) == 0 && !f.json {
		fmt.Fprintln(out, "No MCP configuration found in Claude Code, Claude Desktop, Cursor, Windsurf, Codex, or ./.mcp.json.")
		return nil
	}
	if reports == nil {
		reports = []scan.FileReport{}
	}
	if f.json {
		if err := scan.WriteJSON(out, reports); err != nil {
			return err
		}
	} else {
		scan.WriteText(out, reports, show, scan.Style{Color: useColor(out, f.noColor), Clean: clean})
	}
	if n := unreadable(reports); n > 0 {
		return fmt.Errorf("%s could not be read", plural(n, "file"))
	}
	if fail {
		if n := scan.Summarize(reports).AtOrAbove(failOn); n > 0 {
			return findingsError{n: n}
		}
	}
	return nil
}

// scanLocations returns the files to scan: the ones named with --file, or
// every supported client plus ./.mcp.json.
func scanLocations(home string, files []string) ([]scanTarget, error) {
	if len(files) > 0 {
		targets := make([]scanTarget, 0, len(files))
		for _, p := range files {
			format := clients.FormatJSON
			if strings.EqualFold(filepath.Ext(p), ".toml") {
				format = clients.FormatCodexTOML
			}
			targets = append(targets, scanTarget{loc: clients.Location{Client: "file", Label: "File", Path: p, Format: format}, required: true})
		}
		return targets, nil
	}
	if home == "" {
		return nil, errors.New("cannot find your home folder; pass --file")
	}
	var targets []scanTarget
	for _, loc := range clients.Locations(home, runtime.GOOS, os.Getenv("APPDATA")) {
		targets = append(targets, scanTarget{loc: loc})
	}
	if abs, err := filepath.Abs(projectConfig); err == nil {
		targets = append(targets, scanTarget{loc: clients.Location{Client: "project", Label: "This project", Path: abs, Format: clients.FormatJSON}})
	}
	return targets, nil
}

type scanTarget struct {
	loc      clients.Location
	required bool // a missing file is an error, not skipped
}

func scanAll(targets []scanTarget, ctx scan.Context) []scan.FileReport {
	var reports []scan.FileReport
	for _, t := range targets {
		data, err := os.ReadFile(t.loc.Path)
		switch {
		case errors.Is(err, os.ErrNotExist) && !t.required:
			continue
		case err != nil:
			reports = append(reports, scan.FileReport{Client: t.loc.Client, Label: t.loc.Label, Path: t.loc.Path,
				Error: "could not read this file: " + err.Error(), Servers: []scan.ServerReport{}})
		default:
			reports = append(reports, scan.File(t.loc, data, ctx))
		}
	}
	return reports
}

// useColor is true for an interactive terminal unless NO_COLOR is set.
func useColor(out io.Writer, disabled bool) bool {
	if disabled || os.Getenv("NO_COLOR") != "" {
		return false
	}
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func unreadable(reports []scan.FileReport) int {
	n := 0
	for _, r := range reports {
		if r.Error != "" {
			n++
		}
	}
	return n
}
