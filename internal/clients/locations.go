package clients

import "path/filepath"

// Format is the configuration syntax a client uses.
type Format int

const (
	FormatJSON Format = iota
	FormatCodexTOML
)

// Location is one client configuration file Roro knows how to edit.
type Location struct {
	Client string // agent name used in policy and logs
	Label  string // name shown to people
	Path   string
	Format Format
}

// Locations lists the user-wide MCP configuration files of supported
// clients. appData is %APPDATA% on Windows and ignored elsewhere.
func Locations(home, goos, appData string) []Location {
	desktop := filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	switch goos {
	case "darwin":
		desktop = filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "windows":
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		desktop = filepath.Join(appData, "Claude", "claude_desktop_config.json")
	}
	return []Location{
		{Client: "claude-code", Label: "Claude Code", Path: filepath.Join(home, ".claude.json"), Format: FormatJSON},
		{Client: "claude-desktop", Label: "Claude Desktop", Path: desktop, Format: FormatJSON},
		{Client: "cursor", Label: "Cursor", Path: filepath.Join(home, ".cursor", "mcp.json"), Format: FormatJSON},
		{Client: "windsurf", Label: "Windsurf", Path: filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), Format: FormatJSON},
		{Client: "codex", Label: "Codex", Path: filepath.Join(home, ".codex", "config.toml"), Format: FormatCodexTOML},
	}
}
