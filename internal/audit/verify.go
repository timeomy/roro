package audit

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"fmt"
)

// Report is the result of Verify.
type Report struct {
	Events            int64
	LastSeq           int64
	Checkpoints       int
	LastCheckpointSeq int64
	// Unsealed counts events after the last checkpoint. They are covered by
	// the hash chain but not yet by a signature, so deleting them would not
	// be detected. Tollgate checkpoints on clean shutdown to keep this at 0.
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
}

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
		rep.LastCheckpointSeq = max(rep.LastCheckpointSeq, c.Seq)
	}
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
