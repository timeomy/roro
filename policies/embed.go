// Package policies embeds the starter Cedar policy written by `roro init`.
package policies

import _ "embed"

// Starter is policies/examples/roro.cedar.
//
//go:embed examples/roro.cedar
var Starter string

// SandboxPlaceholder is the path prefix in Starter that `roro init`
// replaces with the user's sandbox directory.
const SandboxPlaceholder = "/sandbox"
