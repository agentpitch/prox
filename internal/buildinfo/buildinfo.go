package buildinfo

import "strings"

// Version is set for release builds with -ldflags -X.
var Version = "dev"

func CurrentVersion() string {
	if version := strings.TrimSpace(Version); version != "" {
		return version
	}
	return "dev"
}
