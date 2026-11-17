package audit

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Report is the result of Verify.
type Report struct {
	Events            int64
	LastSeq           int64
	Checkpoints       int
	LastCheckpointSeq int64
	// Anchor is "<seq>:<entry_hash>" of the latest valid checkpoint. Record
	// it somewhere the log's writer cannot change (a ticket, a remote log,
	// another machine) and pass it back with VerifyOptions.Expect: a later
	// copy of the log that was rolled back past it then fails.
	Anchor string
	// Unsealed counts events after the last checkpoint. They are covered by
	// the hash chain but not yet by a signature, so deleting them would not
	// be detected. Roro checkpoints on clean shutdown to keep this at 0.
	Unsealed int64
	Problems []string
}

// OK reports whether verification found no problems.
func (r Report) OK() bool { return len(r.Problems) == 0 }

const maxProblems = 50

func (r *Report) fail(format string, args ...any) {
	if len(r.Problems) < maxProblems {
		r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
	}
}

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// PublicKey verifies checkpoint signatures.
	PublicKey ed25519.PublicKey
	// RequireSealed fails verification if any event is after the last
	// checkpoint.
	RequireSealed bool
	// Expect lists anchors (from an earlier Report.Anchor) the log must
	// still contain, with the same hash. This is what detects a rollback to
	// an earlier checkpoint, which the log alone cannot show.
	Expect []Anchor
}

// Anchor pins one event: the log must still hold Seq with entry hash Hash.
type Anchor struct {
	Seq  int64
	Hash string
}

// ParseAnchor parses "<seq>:<hex entry hash>".
func ParseAnchor(s string) (Anchor, error) {
	var a Anchor
	seqStr, hash, ok := strings.Cut(s, ":")
	seq, err := strconv.ParseInt(seqStr, 10, 64)
	if !ok || err != nil || seq < 1 || len(hash) != 64 {
		return a, fmt.Errorf("anchor %q: want <seq>:<64 hex chars>, as printed by verify", s)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return a, fmt.Errorf("anchor %q: hash is not hex", s)
	}
	return Anchor{Seq: seq, Hash: strings.ToLower(hash)}, nil
}

func (a Anchor) String() string { return fmt.Sprintf("%d:%s", a.Seq, a.Hash) }

// Verify recomputes the hash chain and checks every checkpoint. It fails if:
//   - a row is missing or out of order (seq gap or prev_hash mismatch),
//   - any hashed field was altered (entry_hash mismatch),
//   - a checkpoint signature is invalid or from an unknown key,
//   - a checkpoint refers to a row that is missing or has a different hash,
//   - the chain ends before the latest checkpoint (truncation),
//   - RequireSealed is set and events exist after the latest checkpoint.
func Verify(ctx context.Context, db *sql.DB, opts VerifyOptions) (Report, error) {
	var rep Report
	if len(opts.PublicKey) != ed25519.PublicKeySize {
		return rep, fmt.Errorf("audit: verify needs an Ed25519 public key")
	}
	hashes, err := verifyChain(ctx, db, &rep)
	if err != nil {
		return rep, err
	}
	cps, err := Checkpoints(ctx, db)
	if err != nil {
		return rep, err
	}
	rep.Checkpoints = len(cps)
	verifyCheckpoints(cps, hashes, opts.PublicKey, &rep)

	if rep.LastCheckpointSeq > rep.LastSeq {
		rep.fail("truncation: chain ends at seq %d but checkpoint covers seq %d", rep.LastSeq, rep.LastCheckpointSeq)
	} else {
		rep.Unsealed = rep.LastSeq - rep.LastCheckpointSeq
	}
	if rep.Events > 0 && rep.Checkpoints == 0 {
		rep.fail("no checkpoints: the log has %d events but no signed checkpoint", rep.Events)
	}
	for _, a := range opts.Expect {
		switch h, ok := hashes[a.Seq]; {
		case a.Seq > rep.LastSeq:
			rep.fail("rollback: expected anchor seq %d, but the log ends at seq %d", a.Seq, rep.LastSeq)
		case !ok:
			rep.fail("anchor seq %d: row is missing or invalid", a.Seq)
		case h != a.Hash:
			rep.fail("anchor seq %d: log has hash %s, anchor recorded %s (log was rewritten)", a.Seq, short(h), short(a.Hash))
		}
	}
	if opts.RequireSealed && rep.Unsealed > 0 {
		rep.fail("unsealed: %d events after the last checkpoint (seq %d)", rep.Unsealed, rep.LastCheckpointSeq)
	}
	return rep, nil
}

// verifyChain walks events in seq order and returns seq -> entry_hash for
// rows whose hash verified.
func verifyChain(ctx context.Context, db *sql.DB, rep *Report) (map[int64]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT "+eventColumns+" FROM events ORDER BY seq")
	if err != nil {
		return nil, fmt.Errorf("audit: verify: %w", err)
	}
	defer rows.Close()
	hashes := map[int64]string{}
	prevSeq, prevHash := int64(0), GenesisHash
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			rep.fail("unreadable row after seq %d: %v", prevSeq, err)
			continue
		}
		rep.Events++
		if e.Seq != prevSeq+1 {
			rep.fail("missing or reordered rows: expected seq %d, found %d", prevSeq+1, e.Seq)
		}
		if e.PrevHash != prevHash {
			rep.fail("seq %d: prev_hash does not match entry_hash of the previous row", e.Seq)
		}
		if got := e.ComputeHash(); got != e.EntryHash {
			rep.fail("seq %d: row was modified (entry_hash mismatch)", e.Seq)
		} else {
			hashes[e.Seq] = e.EntryHash
		}
		prevSeq, prevHash = e.Seq, e.EntryHash
	}
	rep.LastSeq = prevSeq
	return hashes, rows.Err()
}

func verifyCheckpoints(cps []Checkpoint, hashes map[int64]string, pub ed25519.PublicKey, rep *Report) {
	keyID := KeyID(pub)
	prevSeq := int64(0)
	for _, c := range cps {
		if c.KeyID != keyID {
			rep.fail("checkpoint %d: signed by unknown key %s (expected %s)", c.ID, c.KeyID, keyID)
			continue
		}
		sig, err := hex.DecodeString(c.Signature)
		if err != nil || !ed25519.Verify(pub, c.SignedMessage(), sig) {
			rep.fail("checkpoint %d (seq %d): invalid signature", c.ID, c.Seq)
			continue
		}
		if c.Seq < prevSeq {
			rep.fail("checkpoint %d: seq %d goes backwards (previous %d)", c.ID, c.Seq, prevSeq)
		}
		prevSeq = max(prevSeq, c.Seq)
		h, ok := hashes[c.Seq]
		switch {
		case c.Seq > rep.LastSeq:
			// reported as truncation by the caller
		case !ok:
			rep.fail("checkpoint %d: row seq %d is missing or invalid", c.ID, c.Seq)
		case h != c.EntryHash:
			rep.fail("checkpoint %d: row seq %d has hash %s, checkpoint signed %s", c.ID, c.Seq, short(h), short(c.EntryHash))
		}
		if ok && h == c.EntryHash && c.Seq >= rep.LastCheckpointSeq {
			rep.Anchor = Anchor{Seq: c.Seq, Hash: c.EntryHash}.String()
		}
		rep.LastCheckpointSeq = max(rep.LastCheckpointSeq, c.Seq)
	}
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
