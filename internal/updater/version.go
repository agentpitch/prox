package updater

import (
	"strconv"
	"strings"
)

type parsedVersion struct {
	major int64
	minor int64
	patch int64
	pre   []string
}

func compareVersions(left, right string) (int, bool) {
	a, ok := parseVersion(left)
	if !ok {
		return 0, false
	}
	b, ok := parseVersion(right)
	if !ok {
		return 0, false
	}
	for _, pair := range [][2]int64{{a.major, b.major}, {a.minor, b.minor}, {a.patch, b.patch}} {
		if pair[0] < pair[1] {
			return -1, true
		}
		if pair[0] > pair[1] {
			return 1, true
		}
	}
	if len(a.pre) == 0 && len(b.pre) == 0 {
		return 0, true
	}
	if len(a.pre) == 0 {
		return 1, true
	}
	if len(b.pre) == 0 {
		return -1, true
	}
	limit := min(len(a.pre), len(b.pre))
	for i := 0; i < limit; i++ {
		if a.pre[i] == b.pre[i] {
			continue
		}
		an, aNumeric := numericIdentifier(a.pre[i])
		bn, bNumeric := numericIdentifier(b.pre[i])
		switch {
		case aNumeric && bNumeric:
			if len(an) < len(bn) || (len(an) == len(bn) && an < bn) {
				return -1, true
			}
			return 1, true
		case aNumeric:
			return -1, true
		case bNumeric:
			return 1, true
		case a.pre[i] < b.pre[i]:
			return -1, true
		default:
			return 1, true
		}
	}
	if len(a.pre) < len(b.pre) {
		return -1, true
	}
	if len(a.pre) > len(b.pre) {
		return 1, true
	}
	return 0, true
}

func parseVersion(raw string) (parsedVersion, bool) {
	value := strings.TrimSpace(raw)
	if len(value) > 64 {
		return parsedVersion{}, false
	}
	if len(value) > 0 && (value[0] == 'v' || value[0] == 'V') {
		value = value[1:]
	}
	if buildIndex := strings.IndexByte(value, '+'); buildIndex >= 0 {
		value = value[:buildIndex]
	}
	core := value
	pre := ""
	if preIndex := strings.IndexByte(value, '-'); preIndex >= 0 {
		core = value[:preIndex]
		pre = value[preIndex+1:]
		if pre == "" {
			return parsedVersion{}, false
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return parsedVersion{}, false
	}
	numbers := [3]int64{}
	for i, part := range parts {
		if part == "" || !allASCIIDigits(part) {
			return parsedVersion{}, false
		}
		number, err := strconv.ParseInt(part, 10, 63)
		if err != nil {
			return parsedVersion{}, false
		}
		numbers[i] = number
	}
	result := parsedVersion{major: numbers[0], minor: numbers[1], patch: numbers[2]}
	if pre == "" {
		return result, true
	}
	for _, identifier := range strings.Split(pre, ".") {
		if identifier == "" || len(identifier) > 32 {
			return parsedVersion{}, false
		}
		for _, ch := range identifier {
			if !(ch >= 'A' && ch <= 'Z') && !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') && ch != '-' {
				return parsedVersion{}, false
			}
		}
		result.pre = append(result.pre, strings.ToLower(identifier))
	}
	return result, true
}

func numericIdentifier(value string) (string, bool) {
	if value == "" || !allASCIIDigits(value) {
		return "", false
	}
	normalized := strings.TrimLeft(value, "0")
	if normalized == "" {
		normalized = "0"
	}
	return normalized, true
}

func allASCIIDigits(value string) bool {
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return value != ""
}
