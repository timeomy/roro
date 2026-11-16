// Package audit implements Tollgate's tamper-evident audit log.
//
// Every event is a row in an append-only SQLite table. Each row stores the
// SHA-256 hash of its own canonical encoding, and that encoding includes the
// previous row's hash, forming a hash chain. Periodically the latest hash is
// signed with an Ed25519 key kept outside the log (a checkpoint). `tollgate
// verify` recomputes the chain and checks every checkpoint signature.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// GenesisHash is prev_hash of the first event: 64 zero hex digits.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// hashDomain versions the canonical encoding.
const hashDomain = "tollgate/audit/event/v1"

// Event kinds.
const (
	KindToolCall   = "tool_call"   // a policy decision on tools/call
	KindToolResult = "tool_result" // the upstream's answer to an allowed call
	KindKill       = "kill"
	KindResume     = "resume"
	KindPinChange  = "pin_change"
	KindPinAccept  = "pin_accept"
	KindSession    = "session"
)

// Event is one audit log entry. Fields marked "hashed" are covered by
// EntryHash; changing any of them breaks verification.
type Event struct {
	Seq          int64     `json:"seq"`           // hashed
	Time         time.Time `json:"ts"`            // hashed, UTC, RFC 3339 with nanoseconds
	Kind         string    `json:"kind"`          // hashed
	Agent        string    `json:"agent"`         // hashed
	Server       string    `json:"server"`        // hashed
	Tool         string    `json:"tool"`          // hashed
	CallID       string    `json:"call_id"`       // hashed: JSON-RPC id of the call
	Session      string    `json:"session"`       // hashed: proxy session id
	ArgsHash     string    `json:"args_hash"`     // hashed: SHA-256 of redacted canonical args
	ArgsPreview  string    `json:"args_preview"`  // hashed: redacted, truncated
	Decision     string    `json:"decision"`      // hashed
	Reason       string    `json:"reason"`        // hashed
	PolicyIDs    string    `json:"policy_ids"`    // hashed: comma-separated
	ApprovalID   string    `json:"approval_id"`   // hashed
	LatencyMS    int64     `json:"latency_ms"`    // hashed: upstream latency
	ResultDigest string    `json:"result_digest"` // hashed: SHA-256 of the raw result
	Detail       string    `json:"detail"`        // hashed: redacted free text
	PrevHash     string    `json:"prev_hash"`     // hashed
	EntryHash    string    `json:"entry_hash"`
}

// TimeFormat is how event times are stored and hashed.
const TimeFormat = time.RFC3339Nano

// ComputeHash returns the hex SHA-256 of the event's canonical encoding.
//
// The encoding is the domain string followed by every hashed field in a fixed
// order, each written as "<byte length>:<bytes>\n". Length prefixes make the
// encoding unambiguous: no two different field lists produce the same bytes.
func (e Event) ComputeHash() string {
	fields := []string{
		hashDomain,
		strconv.FormatInt(e.Seq, 10),
		e.Time.UTC().Format(TimeFormat),
		e.Kind, e.Agent, e.Server, e.Tool, e.CallID, e.Session,
		e.ArgsHash, e.ArgsPreview,
		e.Decision, e.Reason, e.PolicyIDs, e.ApprovalID,
		strconv.FormatInt(e.LatencyMS, 10),
		e.ResultDigest, e.Detail,
		e.PrevHash,
	}
	h := sha256.New()
	for _, f := range fields {
		h.Write([]byte(strconv.Itoa(len(f))))
		h.Write([]byte{':'})
		h.Write([]byte(f))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Checkpoint is a signed statement that the chain had EntryHash at Seq.
type Checkpoint struct {
	ID        int64     `json:"id"`
	Seq       int64     `json:"seq"`
	EntryHash string    `json:"entry_hash"`
	Time      time.Time `json:"ts"`
	KeyID     string    `json:"key_id"`
	Signature string    `json:"signature"` // hex Ed25519 signature
}

const checkpointDomain = "tollgate/audit/checkpoint/v1"

// SignedMessage returns the bytes a checkpoint signature covers.
func (c Checkpoint) SignedMessage() []byte {
	return []byte(checkpointDomain + "\n" +
		strconv.FormatInt(c.Seq, 10) + "\n" +
		c.EntryHash + "\n" +
		c.Time.UTC().Format(TimeFormat) + "\n" +
		c.KeyID + "\n")
}
