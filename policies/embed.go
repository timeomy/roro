// Package policies embeds the Cedar policies written by `roro init` and
// `roro protect`.
package policies

import _ "embed"

// Starter is policies/examples/roro.cedar.
//
//go:embed examples/roro.cedar
var Starter string

// SandboxPlaceholder is the path prefix in Starter that `roro init`
// replaces with the user's sandbox directory.
const SandboxPlaceholder = "/sandbox"

// Everyday is policies/examples/everyday.cedar, the allow-by-default policy
// `roro protect` writes for people who do not want to author rules.
//
//go:embed examples/everyday.cedar
var Everyday string
