package httpclient

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// proxyForURL returns a WinHTTP named HTTP proxy, or an empty string for a
// direct connection. Read the environment only on explicit update requests;
// there is no background proxy discovery or DNS resolution for NO_PROXY.
func proxyForURL(destination *url.URL) (string, error) {
	return proxyFromEnvironment(destination, os.Getenv)
}

func proxyFromEnvironment(destination *url.URL, getenv func(string) string) (string, error) {
	if destination == nil || (destination.Scheme != "http" && destination.Scheme != "https") || destination.Hostname() == "" {
		return "", errors.New("invalid proxy destination")
	}
	first := func(upper, lower string) string {
		if value := getenv(upper); value != "" {
			return value
		}
		return getenv(lower)
	}
	host := strings.ToLower(destination.Hostname())
	if host == "localhost" {
		return "", nil
	}
	if address, err := netip.ParseAddr(host); err == nil && address.IsLoopback() {
		return "", nil
	}
	port := destination.Port()
	if port == "" {
		port = "80"
		if destination.Scheme == "https" {
			port = "443"
		}
	}
	if bypassProxy(host, port, first("NO_PROXY", "no_proxy")) {
		return "", nil
	}
	raw := first("HTTPS_PROXY", "https_proxy")
	if destination.Scheme == "http" {
		raw = first("HTTP_PROXY", "http_proxy")
		// HTTP_PROXY can originate from an attacker-controlled CGI header.
		if raw != "" && getenv("REQUEST_METHOD") != "" {
			return "", errors.New("refusing HTTP proxy environment in CGI")
		}
	}
	if raw == "" {
		return "", nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	proxy, err := url.Parse(raw)
	if err != nil {
		// A URL parse error may contain credentials, so do not propagate it.
		return "", errors.New("invalid update proxy address")
	}
	if proxy.Scheme != "http" {
		return "", errors.New("update proxy must use HTTP; HTTPS and SOCKS proxy protocols are not supported")
	}
	if proxy.User != nil {
		return "", errors.New("update proxy credentials in the environment are not supported")
	}
	if proxy.Hostname() == "" || (proxy.Path != "" && proxy.Path != "/") || proxy.RawQuery != "" || proxy.ForceQuery || proxy.Fragment != "" {
		return "", errors.New("update proxy must be an HTTP origin without a path, query, or fragment")
	}
	proxyHost := proxy.Hostname()
	if strings.ContainsAny(proxyHost, " \t\r\n\x00/\\;=") {
		return "", errors.New("invalid update proxy host")
	}
	if strings.Contains(proxyHost, ":") {
		address, err := netip.ParseAddr(proxyHost)
		if err != nil || address.Zone() != "" {
			return "", errors.New("invalid update proxy IP address")
		}
	}
	proxyPort := proxy.Port()
	if proxyPort == "" {
		proxyPort = "80"
	}
	portNumber, err := strconv.Atoi(proxyPort)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("invalid update proxy port")
	}
	return net.JoinHostPort(proxyHost, proxyPort), nil
}

// NO_PROXY uses the common Go environment syntax: exact IPs, CIDRs, domains,
// domains restricted to subdomains by a leading dot (or *.), and optional
// ports. Bad entries are ignored. An unprefixed domain includes its apex.
func bypassProxy(host, port, exclusions string) bool {
	address, addressErr := netip.ParseAddr(host)
	for _, entry := range strings.Split(exclusions, ",") {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if entry == "*" {
			return true
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			if addressErr == nil && (prefix.Contains(address) || prefix.Contains(address.Unmap())) {
				return true
			}
			continue
		}
		entryHost, entryPort, err := net.SplitHostPort(entry)
		if err != nil {
			entryHost, entryPort = entry, ""
		}
		if entryHost == "" || (entryPort != "" && entryPort != port) {
			continue
		}
		if excluded, err := netip.ParseAddr(entryHost); err == nil {
			if addressErr == nil && excluded.Unmap() == address.Unmap() {
				return true
			}
			continue
		}
		if addressErr == nil {
			continue
		}
		if strings.HasPrefix(entryHost, "*.") {
			entryHost = entryHost[1:]
		}
		includeApex := !strings.HasPrefix(entryHost, ".")
		if includeApex {
			entryHost = "." + entryHost
		}
		if strings.HasSuffix(host, entryHost) || (includeApex && host == entryHost[1:]) {
			return true
		}
	}
	return false
}
