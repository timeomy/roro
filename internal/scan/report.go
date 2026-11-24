package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// JSONReport is the --json output. Its shape is part of the CLI contract.
type JSONReport struct {
	Version int          `json:"version"`
	Files   []FileReport `json:"files"`
	Summary Summary      `json:"summary"`
}

// WriteJSON writes reports as one JSON document.
func WriteJSON(w io.Writer, reports []FileReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(JSONReport{Version: 1, Files: reports, Summary: Summarize(reports)})
}

// Style controls text output. Clean, when set, is applied to every string
// that came from a configuration file, so a hostile file cannot send
// terminal control sequences.
type Style struct {
	Color bool
	Clean func(string) string
}

func (st Style) c(s string) string {
	if st.Clean == nil {
		return s
	}
	return st.Clean(s)
}

func (st Style) paint(code, s string) string {
	if !st.Color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (st Style) sev(s Severity) string {
	label := fmt.Sprintf("%-6s", strings.ToUpper(s.String()))
	switch s {
	case High:
		return st.paint("1;31", label)
	case Medium:
		return st.paint("33", label)
	case Low:
		return st.paint("36", label)
	default:
		return st.paint("2", label)
	}
}

// WriteText writes a report for people. Findings below min are counted in
// the summary but not listed, so the default view stays short.
func WriteText(w io.Writer, reports []FileReport, min Severity, st Style) {
	for _, f := range reports {
		fmt.Fprintf(w, "\n%s  %s\n", st.paint("1", f.Label), st.paint("2", st.c(f.Path)))
		if f.Error != "" {
			fmt.Fprintf(w, "  %s\n", st.c(f.Error))
			continue
		}
		if len(f.Servers) == 0 {
			fmt.Fprintln(w, "  no MCP servers")
		}
		for _, s := range f.Servers {
			writeServer(w, s, min, st)
		}
	}
	writeSummary(w, Summarize(reports), min, st)
}

func writeServer(w io.Writer, s ServerReport, min Severity, st Style) {
	name := st.c(s.Name)
	if s.Scope != "" {
		name += st.paint("2", "  (project "+st.c(s.Scope)+")")
	}
	shown, hidden := 0, 0
	for _, fd := range s.Findings {
		switch {
		case fd.Severity >= min:
			shown++
		case fd.Severity > Info:
			hidden++
		}
	}
	if shown == 0 && hidden > 0 {
		fmt.Fprintf(w, "  %s  %s\n", name, st.paint("2", fmt.Sprintf("%d below %s not shown", hidden, min)))
		return
	}
	if shown == 0 {
		fmt.Fprintf(w, "  %s %s\n", st.paint("32", "ok"), name)
		return
	}
	fmt.Fprintf(w, "  %s\n", name)
	for _, fd := range s.Findings {
		if fd.Severity < min {
			continue
		}
		fmt.Fprintf(w, "    %s %s  %s\n", st.sev(fd.Severity), fd.Title, st.paint("2", fd.Rule))
		fmt.Fprintf(w, "           %s\n", st.c(fd.Detail))
		fmt.Fprintf(w, "           %s %s\n", st.paint("2", "fix:"), st.c(fd.Fix))
	}
}

func writeSummary(w io.Writer, sum Summary, min Severity, st Style) {
	fmt.Fprintf(w, "\nScanned %s in %s. ", count(sum.Servers, "server"), count(sum.Files, "file"))
	parts := []string{}
	for _, s := range []Severity{High, Medium, Low, Info} {
		if n := sum.bySev[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	if len(parts) == 0 {
		fmt.Fprintln(w, st.paint("32", "No issues found."))
		return
	}
	fmt.Fprintf(w, "Found %s.\n", strings.Join(parts, ", "))
	if hidden := sum.AtOrAbove(Info) - sum.AtOrAbove(min); hidden > 0 {
		fmt.Fprintf(w, "%s below %s not shown; use --show %s to list them.\n", count(hidden, "finding"), min, lowestShown(sum))
	}
}

func lowestShown(sum Summary) Severity {
	for _, s := range []Severity{Info, Low, Medium} {
		if sum.bySev[s] > 0 {
			return s
		}
	}
	return Info
}

func count(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
