package policy

import (
	"fmt"
	"regexp"
)

// Matcher is a named regular expression evaluated against every string in a
// tool call's arguments (keys excluded, nested values included). Its result is
// a boolean fact in context.matches; Cedar decides what the fact means.
type Matcher struct {
	Name string
	re   *regexp.Regexp
}

// NewMatcher compiles a matcher. Go regular expressions are RE2, so matching
// time is linear in input size.
func NewMatcher(name, expr string) (Matcher, error) {
	re, err := regexp.Compile(expr)
	if err != nil {
		return Matcher{}, fmt.Errorf("matcher %q: %w", name, err)
	}
	return Matcher{Name: name, re: re}, nil
}

// EvaluateMatchers returns name -> whether any string argument matched.
func EvaluateMatchers(ms []Matcher, args map[string]any) map[string]bool {
	out := make(map[string]bool, len(ms))
	if len(ms) == 0 {
		return out
	}
	var strs []string
	collectStrings(args, &strs)
	for _, m := range ms {
		for _, s := range strs {
			if m.re.MatchString(s) {
				out[m.Name] = true
				break
			}
		}
	}
	return out
}

func collectStrings(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case map[string]any:
		for _, e := range t {
			collectStrings(e, out)
		}
	case []any:
		for _, e := range t {
			collectStrings(e, out)
		}
	}
}

// MatcherNames lists matcher names, for exposing every name to Cedar even
// when it did not match.
func MatcherNames(ms []Matcher) []string {
	names := make([]string, len(ms))
	for i, m := range ms {
		names[i] = m.Name
	}
	return names
}
