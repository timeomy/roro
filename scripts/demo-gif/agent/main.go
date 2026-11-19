// Drives the "notes" server exactly as the Cursor config launches it.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	raw, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".cursor", "mcp.json"))
	if err != nil {
		panic(err)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		panic(err)
	}
	e := cfg.MCPServers["notes"]
	ctx := context.Background()
	c := mcp.NewClient(&mcp.Implementation{Name: "cursor", Version: "1"}, nil)
	s, err := c.Connect(ctx, &mcp.CommandTransport{Command: exec.Command(e.Command, e.Args...)}, nil)
	if err != nil {
		panic(err)
	}
	defer s.Close()
	var calls []struct {
		Tool string         `json:"tool"`
		Args map[string]any `json:"args"`
	}
	if err := json.Unmarshal([]byte(os.Args[1]), &calls); err != nil {
		panic(err)
	}
	for _, k := range calls {
		res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: k.Tool, Arguments: k.Args})
		if err != nil {
			fmt.Println(k.Tool, "error:", err)
			continue
		}
		fmt.Println(k.Tool, "isError:", res.IsError)
	}
}
