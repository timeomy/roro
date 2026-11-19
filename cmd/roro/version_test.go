package main

import "testing"

func TestResolveVersion(t *testing.T) {
	cases := []struct{ name, ldflag, module, want string }{
		{"release build keeps the ldflags value", "v0.2.2", "v0.2.1", "v0.2.2"},
		{"go install uses the module version", "dev", "v0.2.2", "v0.2.2"},
		{"local build has no module version", "dev", "(devel)", "dev"},
		{"missing build info", "dev", "", "dev"},
	}
	for _, c := range cases {
		if got := resolveVersion(c.ldflag, c.module); got != c.want {
			t.Errorf("%s: resolveVersion(%q, %q) = %q, want %q", c.name, c.ldflag, c.module, got, c.want)
		}
	}
}
