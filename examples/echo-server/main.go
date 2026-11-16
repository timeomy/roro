// Command echo-server is a tiny, harmless MCP server used by Tollgate's
// pass-through tests and the quickstart. It speaks MCP over stdio.
//
// Tools:
//   - echo: returns the given text unchanged (also as structured output).
//   - fail: always returns a tool error, to check that errors pass through.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoArgs struct {
	Text string `json:"text" jsonschema:"text to echo back"`
}

type echoOut struct {
	Text   string `json:"text"`
	Length int    `json:"length"`
}

type failArgs struct {
	Reason string `json:"reason,omitempty" jsonschema:"message to put in the tool error"`
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "tollgate-echo", Version: "0.1.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "Return the given text unchanged.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, echoOut, error) {
		return nil, echoOut{Text: in.Text, Length: len(in.Text)}, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "fail",
		Description: "Always fail with a tool error.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in failArgs) (*mcp.CallToolResult, any, error) {
		reason := in.Reason
		if reason == "" {
			reason = "requested failure"
		}
		return nil, nil, fmt.Errorf("fail tool: %s", reason)
	})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "echo-server:", err)
		os.Exit(1)
	}
}
