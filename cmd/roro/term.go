package main

import (
	"fmt"
	"strings"
	"unicode"
)

// maxFieldLen caps a single untrusted field printed to the terminal.
const maxFieldLen = 256

// clean makes untrusted text (tool names from upstream servers, arguments,
// reasons) safe to print on a terminal: control characters, including C1
// controls such as U+009B (CSI), and bidi overrides are shown as \uXXXX
// escapes, so they cannot move the cursor, rewrite earlier lines of an
// approval prompt, or reorder text. Long fields are cut.
func clean(s string) string { return cleanText(s, false) }

// cleanMultiline is clean, but keeps newlines (for indented JSON).
func cleanMultiline(s string) string { return cleanText(s, true) }

func cleanText(s string, keepNewlines bool) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if !keepNewlines && n >= maxFieldLen {
			b.WriteString("…")
			break
		}
		n++
		switch {
		case r == '\n' && keepNewlines:
			b.WriteRune(r)
		case r == unicode.ReplacementChar, unicode.IsControl(r), isBidiControl(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isBidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}
