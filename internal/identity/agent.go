// Package identity defines agent principals: the named identities every
// Roro decision is attributed to.
package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Agent is a named agent principal, for example agent::research-bot.
type Agent struct {
	// Name is the stable identifier used in policy (Roro::Agent::"<Name>").
	Name string
	// Client is the MCP host or framework the agent runs in (for example
	// "cursor" or "claude-desktop"). Informational, available to policy.
	Client string
	// Owner is the human or team accountable for the agent. Informational,
	// available to policy.
	Owner string
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrNoAgent is returned when no agent identity was configured.
var ErrNoAgent = errors.New("no agent identity: set agent.name in roro.yaml, RORO_AGENT, or --agent")

// Validate checks that the agent name is usable as a principal id.
func (a Agent) Validate() error {
	if a.Name == "" {
		return ErrNoAgent
	}
	if !namePattern.MatchString(a.Name) {
		return fmt.Errorf("invalid agent name %q: use 1-64 lowercase letters, digits, '.', '_' or '-', starting with a letter or digit", a.Name)
	}
	return nil
}

// String returns the display form, for example "agent::cursor".
func (a Agent) String() string { return "agent::" + a.Name }

// TokenPrefix marks Roro agent tokens so they are easy to recognise (and
// redact) in logs.
const TokenPrefix = "tgk_"

// NewToken returns a fresh random bearer token and its SHA-256 hex digest.
// Only the digest belongs in configuration.
func NewToken() (token, digest string, err error) {
	token = TokenPrefix + rand.Text()
	return token, HashToken(token), nil
}

// HashToken returns the hex SHA-256 of a bearer token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// TokenEntry binds a token digest to an agent.
type TokenEntry struct {
	Agent  Agent
	Digest string
}

// Directory resolves bearer tokens to agents.
type Directory struct {
	entries []TokenEntry
}

// NewDirectory validates the entries and builds a directory.
func NewDirectory(entries []TokenEntry) (*Directory, error) {
	seen := map[string]bool{}
	for _, e := range entries {
		if err := e.Agent.Validate(); err != nil {
			return nil, err
		}
		d := strings.ToLower(e.Digest)
		if len(d) != 64 || !isHex(d) {
			return nil, fmt.Errorf("agent %q: token_sha256 must be 64 hex characters", e.Agent.Name)
		}
		if seen[d] {
			return nil, fmt.Errorf("agent %q: token digest used by more than one agent", e.Agent.Name)
		}
		seen[d] = true
	}
	return &Directory{entries: entries}, nil
}

// Lookup returns the agent for a bearer token. It compares digests in
// constant time and checks every entry, so timing does not reveal which
// entry matched.
func (d *Directory) Lookup(token string) (Agent, bool) {
	if d == nil || token == "" {
		return Agent{}, false
	}
	got := []byte(HashToken(token))
	var found Agent
	ok := false
	for _, e := range d.entries {
		if subtle.ConstantTimeCompare(got, []byte(strings.ToLower(e.Digest))) == 1 {
			found, ok = e.Agent, true
		}
	}
	return found, ok
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}
