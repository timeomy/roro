// Package policies embeds the starter Cedar policy written by `tollgate init`.
package policies

import _ "embed"

// Starter is policies/examples/tollgate.cedar.
//
//go:embed examples/tollgate.cedar
var Starter string

// SandboxPlaceholder is the path prefix in Starter that `tollgate init`
// replaces with the user's sandbox directory.
const SandboxPlaceholder = "/sandbox"
