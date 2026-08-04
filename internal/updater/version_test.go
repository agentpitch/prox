package updater

import (
	"strings"
	"testing"
)

func TestCompareVersionsSemverOrdering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		left       string
		right      string
		comparison int
	}{
		{name: "minor numbers are numeric", left: "v0.9", right: "v0.10", comparison: -1},
		{name: "missing patch is zero", left: "v1.2", right: "v1.2.0", comparison: 0},
		{name: "patch numbers are numeric", left: "v1.2.9", right: "v1.2.10", comparison: -1},
		{name: "numeric prerelease identifiers are numeric", left: "v0.43-rc.2", right: "v0.43-rc.10", comparison: -1},
		{name: "large numeric prerelease identifiers are numeric", left: "v1.2-90000000000000000000", right: "v1.2-100000000000000000000", comparison: -1},
		{name: "numeric identifier sorts before text", left: "v1.0.0-alpha.1", right: "v1.0.0-alpha.beta", comparison: -1},
		{name: "shorter matching prerelease sorts first", left: "v1.0.0-alpha", right: "v1.0.0-alpha.1", comparison: -1},
		{name: "prerelease sorts below stable", left: "v0.43-rc.4", right: "v0.43", comparison: -1},
		{name: "comparison is case insensitive", left: "V0.43-RC.4", right: "v0.43-rc.4", comparison: 0},
		{name: "build metadata does not affect precedence", left: "v1.2.3+build.1", right: "v1.2.3+build.2", comparison: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, known := compareVersions(test.left, test.right)
			if !known {
				t.Fatalf("compareVersions(%q, %q) reported an unknown comparison", test.left, test.right)
			}
			if got != test.comparison {
				t.Fatalf("compareVersions(%q, %q) = %d, want %d", test.left, test.right, got, test.comparison)
			}

			reverse, reverseKnown := compareVersions(test.right, test.left)
			if !reverseKnown {
				t.Fatalf("reverse compareVersions(%q, %q) reported an unknown comparison", test.right, test.left)
			}
			if reverse != -test.comparison {
				t.Fatalf("reverse compareVersions(%q, %q) = %d, want %d", test.right, test.left, reverse, -test.comparison)
			}
		})
	}
}

func TestCompareVersionsRejectsUnsupportedValues(t *testing.T) {
	t.Parallel()

	invalid := []string{
		"",
		"v1",
		"v1.2.3.4",
		"v1.two",
		"v1.2-",
		"v1.2-alpha..1",
		"v1.2-alpha_1",
		"dev-1a2b3c4",
		"v9223372036854775808.0",
		"v1.2-" + strings.Repeat("a", 65),
	}

	for _, value := range invalid {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, known := compareVersions(value, "v1.2.3"); known {
				t.Fatalf("compareVersions(%q, %q) unexpectedly accepted an unsupported version", value, "v1.2.3")
			}
		})
	}
}
