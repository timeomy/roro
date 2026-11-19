// Stand-in MCP server for the README demo recording.
package main

import (
	"context"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type searchArgs struct {
	Query string `json:"query"`
}
type saveArgs struct {
	Text string `json:"text"`
}
type out struct {
	Result string `json:"result"`
}

func main() {
	s := mcp.NewServer(&mcp.Implementation{Name: "notes", Version: "1.0.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "search", Description: "Search your notes."},
		func(_ context.Context, _ *mcp.CallToolRequest, in searchArgs) (*mcp.CallToolResult, out, error) {
			return nil, out{Result: "2 notes match " + in.Query}, nil
		})
	mcp.AddTool(s, &mcp.Tool{Name: "save", Description: "Save a note."},
		func(_ context.Context, _ *mcp.CallToolRequest, in saveArgs) (*mcp.CallToolResult, out, error) {
			return nil, out{Result: "saved"}, nil
		})
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		os.Exit(1)
	}
}
