package httpclient

import (
	"net/url"
	"strings"
	"testing"
)

func TestProxyEnvironmentSelection(t *testing.T) {
	for _, tc := range []struct {
		name, destination string
		env               map[string]string
		want              string
		fail              bool
	}{
		{"none", "https://api.github.com/", nil, "", false},
		{"upper priority", "https://api.github.com/", map[string]string{"HTTPS_PROXY": "http://upper:8080", "https_proxy": "http://lower:8081"}, "upper:8080", false},
		{"lower fallback", "https://api.github.com/", map[string]string{"HTTPS_PROXY": "", "https_proxy": "proxy:8080"}, "proxy:8080", false},
		{"http", "http://example.test/", map[string]string{"HTTP_PROXY": "proxy", "HTTPS_PROXY": "wrong:123"}, "proxy:80", false},
		{"https separate", "https://example.test/", map[string]string{"HTTP_PROXY": "proxy"}, "", false},
		{"ipv6", "https://example.test/", map[string]string{"HTTPS_PROXY": "http://[::1]:8080/"}, "[::1]:8080", false},
		{"localhost bypass", "https://LOCALHOST:123/", map[string]string{"HTTPS_PROXY": "socks5://wrong:1"}, "", false},
		{"ipv4 bypass", "http://127.8.9.10:123/", map[string]string{"HTTP_PROXY": "wrong:1", "REQUEST_METHOD": "GET"}, "", false},
		{"ipv6 bypass", "https://[::1]/", map[string]string{"HTTPS_PROXY": "wrong:1"}, "", false},
		{"mapped loopback", "https://[::ffff:127.0.0.1]/", map[string]string{"HTTPS_PROXY": "wrong:1"}, "", false},
		{"cgi http", "http://example.test/", map[string]string{"HTTP_PROXY": "proxy", "REQUEST_METHOD": "GET"}, "", true},
		{"cgi https", "https://example.test/", map[string]string{"HTTPS_PROXY": "proxy", "REQUEST_METHOD": "GET"}, "proxy:80", false},
		{"no proxy priority", "https://example.test/", map[string]string{"HTTPS_PROXY": "proxy", "NO_PROXY": "example.test", "no_proxy": "wrong.test"}, "", false},
		{"lower no proxy", "https://example.test/", map[string]string{"HTTPS_PROXY": "proxy", "no_proxy": "example.test"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			destination, err := url.Parse(tc.destination)
			if err != nil {
				t.Fatal(err)
			}
			got, err := proxyFromEnvironment(destination, func(name string) string { return tc.env[name] })
			if (err != nil) != tc.fail || got != tc.want {
				t.Fatalf("got %q, %v; want %q, error=%v", got, err, tc.want, tc.fail)
			}
		})
	}
}

func TestNoProxyMatchers(t *testing.T) {
	for _, tc := range []struct {
		host, port, exclusion string
		want                  bool
	}{
		{"api.github.com", "443", "github.com", true},
		{"github.com", "443", "github.com", true},
		{"evilgithub.com", "443", "github.com", false},
		{"github.com.attacker.test", "443", "github.com", false},
		{"github.com", "443", ".github.com", false},
		{"api.github.com", "443", ".github.com", true},
		{"api.github.com", "443", "*.github.com", true},
		{"github.com", "443", "*.github.com", false},
		{"api.github.com", "443", " API.GITHUB.COM:443 ", true},
		{"api.github.com", "443", "api.github.com:80", false},
		{"api.github.com", "443", ", bad.invalid, github.com", true},
		{"api.github.com", "443", "*", true},
		{"192.0.2.3", "443", "192.0.2.3", true},
		{"192.0.2.3", "443", "192.0.2.3:443", true},
		{"192.0.2.3", "443", "192.0.2.3:80", false},
		{"192.0.2.3", "443", "192.0.2.0/24", true},
		{"192.0.3.3", "443", "192.0.2.0/24", false},
		{"2001:db8::1", "443", "2001:db8::1", true},
		{"2001:db8::1", "443", "[2001:db8::1]:443", true},
		{"2001:db8::1", "443", "[2001:db8::1]:80", false},
		{"2001:db8::1", "443", "2001:db8::/32", true},
		{"::ffff:192.0.2.3", "443", "192.0.2.3", true},
		{"::ffff:192.0.2.3", "443", "192.0.2.0/24", true},
		{"api.github.com", "443", "192.0.2.0/24", false},
		{"192.0.2.3", "443", ".2.3", false},
	} {
		if got := bypassProxy(tc.host, tc.port, tc.exclusion); got != tc.want {
			t.Errorf("bypass(%q,%q,%q)=%v; want %v", tc.host, tc.port, tc.exclusion, got, tc.want)
		}
	}
}

func TestProxyErrorsDoNotDiscloseEnvironmentSecrets(t *testing.T) {
	destination, _ := url.Parse("https://api.github.com/")
	for _, raw := range []string{
		"http://user:secret@proxy:8080", "https://proxy:8080", "socks5://proxy:1080", "http://user:secret%zz@proxy", "http://proxy:secret", "http://proxy:0", "http://proxy:65536", "http://proxy/path", "http://proxy?secret=value", "http://proxy#secret", "http://", "http://[::1%25secret]:8080", "http://proxy;secret:80",
	} {
		got, err := proxyFromEnvironment(destination, func(name string) string {
			if name == "HTTPS_PROXY" {
				return raw
			}
			return ""
		})
		if err == nil || got != "" || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), raw) {
			t.Errorf("unsafe proxy error/output for test case: output=%q error=%v", got, err)
		}
	}
}
