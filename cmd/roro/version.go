package main

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is set at build time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Roro version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "roro %s (%s, %s/%s, mcp-go-sdk %s)\n",
				version, runtime.Version(), runtime.GOOS, runtime.GOARCH, sdkVersion())
			return err
		},
	}
}

func sdkVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/modelcontextprotocol/go-sdk" {
			return dep.Version
		}
	}
	return "unknown"
}
