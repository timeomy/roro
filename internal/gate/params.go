package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
)

// maxJSONDepth bounds nesting in tools/call params.
const maxJSONDepth = 64

// toolNamePattern is the set of tool names Tollgate accepts in a call. It
// keeps names printable (no control characters reach an approval prompt or
// log table) and bounded in length.
var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)

var errInvalidJSON = errors.New("params are not valid JSON")

// jsonFrame is one open object or array while scanning.
type jsonFrame struct {
	object    bool
	keys      map[string]string // case-folded key -> key as sent
	expectKey bool
}

// checkUnambiguous rejects JSON that different parsers could read
// differently: an object with a repeated key, or with two keys that differ
// only by case. Go's encoding/json matches struct fields case-insensitively
// and keeps the last duplicate; other parsers keep the first or match
// exactly. Tollgate decides on one reading and the upstream must see the
// same one, so such input is refused rather than guessed at.
func checkUnambiguous(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []*jsonFrame
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errInvalidJSON
		}
		if n := len(stack); n > 0 && stack[n-1].expectKey {
			if key, ok := tok.(string); ok {
				if err := addKey(stack[n-1], key); err != nil {
					return err
				}
				continue
			}
		}
		switch d := tok.(type) {
		case json.Delim:
			if d == '{' || d == '[' {
				if len(stack) >= maxJSONDepth {
					return fmt.Errorf("params nest deeper than %d levels", maxJSONDepth)
				}
				stack = append(stack, &jsonFrame{object: d == '{', keys: map[string]string{}, expectKey: d == '{'})
				continue
			}
			stack = stack[:len(stack)-1]
			valueDone()
		default:
			valueDone()
		}
	}
}

func addKey(f *jsonFrame, key string) error {
	folded := foldKey(key)
	if prev, dup := f.keys[folded]; dup {
		if prev == key {
			return fmt.Errorf("duplicate key %q", truncate(key, 64))
		}
		return fmt.Errorf("keys %q and %q differ only by case", truncate(prev, 64), truncate(key, 64))
	}
	f.keys[folded] = key
	f.expectKey = false
	return nil
}

// canonicalParams parses tools/call params into their top-level members,
// after checking they are unambiguous. The gate decides on, and forwards,
// exactly these members.
func canonicalParams(raw []byte) (map[string]json.RawMessage, error) {
	if err := checkUnambiguous(raw); err != nil {
		return nil, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, errors.New("tools/call params must be an object")
	}
	return members, nil
}

// foldKey maps every rune to the smallest member of its Unicode case-folding
// orbit, so keys that any case-insensitive matcher treats as equal (including
// "K" vs the Kelvin sign, "s" vs long s) fold to the same string.
func foldKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < low {
				low = f
			}
		}
		b.WriteRune(low)
	}
	return b.String()
}
