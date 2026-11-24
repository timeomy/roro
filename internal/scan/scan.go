// Package scan checks MCP client configurations for risky server entries.
//
// It is static: it reads configuration text and never starts a server,
// connects to one, or sends anything over the network. That keeps a scan
// safe to run on an untrusted configuration, and means it cannot see what a
// server does at run time; that is the proxy's job.
package scan

import (
	"cmp"
	"slices"

	"github.com/timeomy/roro/internal/clients"
)

// Severity ranks a finding. Higher is worse.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
)

var severityNames = map[Severity]string{Info: "info", Low: "low", Medium: "medium", High: "high"}

func (s Severity) String() string { return severityNames[s] }

// MarshalText writes the severity as its name in JSON output.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity reads a severity name. ok is false for unknown names.
func ParseSeverity(name string) (Severity, bool) {
	for s, n := range severityNames {
		if n == name {
			return s, true
		}
	}
	return Info, false
}

// Finding is one problem with one server entry.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"` // never contains a secret value
	Fix      string   `json:"fix"`
}

// ServerReport is everything found for one server entry.
type ServerReport struct {
	Name     string    `json:"name"`
	Scope    string    `json:"scope,omitempty"`
	Kind     string    `json:"kind"` // "local", "remote", or "unknown"
	Findings []Finding `json:"findings"`
}

// FileReport is the result of scanning one configuration file.
type FileReport struct {
	Client  string         `json:"client"`
	Label   string         `json:"label"`
	Path    string         `json:"path"`
	Error   string         `json:"error,omitempty"`
	Servers []ServerReport `json:"servers"`
}

// Context carries facts about the machine that some checks need.
type Context struct {
	Home string // the user's home directory, for broad-path checks
}

// File scans one configuration file's contents. A file that cannot be
// parsed gives a report with Error set and no servers.
func File(loc clients.Location, data []byte, ctx Context) FileReport {
	rep := FileReport{Client: loc.Client, Label: loc.Label, Path: loc.Path, Servers: []ServerReport{}}
	servers, err := clients.ListServers(loc.Format, data)
	if err != nil {
		rep.Error = "could not read this file: " + err.Error()
		return rep
	}
	for _, s := range servers {
		rep.Servers = append(rep.Servers, Server(s, ctx))
	}
	return rep
}

// Server runs every check on one server entry. Findings are sorted worst
// first, then by rule.
func Server(s clients.Server, ctx Context) ServerReport {
	r := ServerReport{Name: s.Name, Scope: s.Scope, Kind: kind(s), Findings: []Finding{}}
	for _, check := range checks {
		r.Findings = append(r.Findings, check(s, ctx)...)
	}
	slices.SortStableFunc(r.Findings, func(a, b Finding) int {
		if c := cmp.Compare(b.Severity, a.Severity); c != 0 {
			return c
		}
		return cmp.Compare(a.Rule, b.Rule)
	})
	return r
}

func kind(s clients.Server) string {
	switch {
	case s.Command != "":
		return "local"
	case s.URL != "":
		return "remote"
	default:
		return "unknown"
	}
}

// Summary counts findings by severity across reports.
type Summary struct {
	Files   int            `json:"files"`
	Servers int            `json:"servers"`
	Counts  map[string]int `json:"counts"`
	Worst   string         `json:"worst"` // "none" when nothing was found
	bySev   map[Severity]int
}

// Summarize totals a set of reports.
func Summarize(reports []FileReport) Summary {
	sum := Summary{Counts: map[string]int{}, bySev: map[Severity]int{}, Worst: "none"}
	worst, found := Info, false
	for _, name := range severityNames {
		sum.Counts[name] = 0
	}
	for _, f := range reports {
		sum.Files++
		for _, s := range f.Servers {
			sum.Servers++
			for _, fd := range s.Findings {
				sum.Counts[fd.Severity.String()]++
				sum.bySev[fd.Severity]++
				worst, found = max(worst, fd.Severity), true
			}
		}
	}
	if found {
		sum.Worst = worst.String()
	}
	return sum
}

// AtOrAbove counts findings at or above a severity.
func (s Summary) AtOrAbove(min Severity) int {
	n := 0
	for sev, c := range s.bySev {
		if sev >= min {
			n += c
		}
	}
	return n
}
