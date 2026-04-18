package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/openai/pitchprox/internal/config"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type directDialer struct{ timeout time.Duration }

func DirectDialer(timeout time.Duration) Dialer { return &directDialer{timeout: timeout} }

func (d *directDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	nd := &net.Dialer{Timeout: d.timeout}
	return nd.DialContext(ctx, network, address)
}

func BuildDialer(cfg config.Config, action config.RuleAction, proxyID, chainID string) (Dialer, error) {
	base := DirectDialer(10 * time.Second)
	switch action {
	case config.ActionDirect:
		return base, nil
	case config.ActionProxy:
		p, ok := findProxy(cfg.Proxies, proxyID)
		if !ok {
			return nil, fmt.Errorf("unknown proxy %q", proxyID)
		}
		return wrapDialer(base, p)
	case config.ActionChain:
		c, ok := findChain(cfg.Chains, chainID)
		if !ok {
			return nil, fmt.Errorf("unknown chain %q", chainID)
		}
		var d Dialer = base
		for _, proxyRef := range c.ProxyIDs {
			p, ok := findProxy(cfg.Proxies, proxyRef)
			if !ok {
				return nil, fmt.Errorf("chain %q references unknown proxy %q", c.Name, proxyRef)
			}
			var err error
			d, err = wrapDialer(d, p)
			if err != nil {
				return nil, err
			}
		}
		return d, nil
	default:
		return nil, fmt.Errorf("unsupported action %q", action)
	}
}

func findProxy(list []config.ProxyProfile, id string) (config.ProxyProfile, bool) {
	for _, p := range list {
		if p.ID == id && p.Enabled {
			return p, true
		}
	}
	return config.ProxyProfile{}, false
}

func findChain(list []config.ProxyChain, id string) (config.ProxyChain, bool) {
	for _, c := range list {
		if c.ID == id && c.Enabled {
			return c, true
		}
	}
	return config.ProxyChain{}, false
}

func wrapDialer(parent Dialer, p config.ProxyProfile) (Dialer, error) {
	switch p.Type {
	case "http":
		return &httpConnectDialer{parent: parent, proxy: p}, nil
	case "socks5":
		return &socks5Dialer{parent: parent, proxy: p}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy type %q", p.Type)
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type httpConnectDialer struct {
	parent Dialer
	proxy  config.ProxyProfile
}

func (d *httpConnectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.parent.DialContext(ctx, "tcp", d.proxy.Address)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
		defer conn.SetDeadline(time.Time{})
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n", address, address)
	if d.proxy.Username != "" || d.proxy.Password != "" {
		token := base64.StdEncoding.EncodeToString([]byte(d.proxy.Username + ":" + d.proxy.Password))
		req += "Proxy-Authorization: Basic " + token + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !strings.Contains(line, " 200 ") {
		_ = conn.Close()
		return nil, fmt.Errorf("http CONNECT failed: %s", strings.TrimSpace(line))
	}
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if line == "\r\n" {
			break
		}
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

type socks5Dialer struct {
	parent Dialer
	proxy  config.ProxyProfile
}

func (d *socks5Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.parent.DialContext(ctx, "tcp", d.proxy.Address)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
		defer conn.SetDeadline(time.Time{})
	}
	methods := []byte{0x00}
	if d.proxy.Username != "" || d.proxy.Password != "" {
		methods = []byte{0x00, 0x02}
	}
	hello := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(hello); err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp[0] != 0x05 {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid socks5 response")
	}
	switch resp[1] {
	case 0x00:
	case 0x02:
		if err := socks5UserPass(conn, d.proxy.Username, d.proxy.Password); err != nil {
			_ = conn.Close()
			return nil, err
		}
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 auth rejected")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil || p < 1 || p > 65535 {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid port %q", port)
	}
	req = append(req, byte(p>>8), byte(p))
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if head[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect failed code=%d", head[1])
	}
	switch head[3] {
	case 0x01:
		_, err = io.CopyN(io.Discard, conn, 4+2)
	case 0x04:
		_, err = io.CopyN(io.Discard, conn, 16+2)
	case 0x03:
		var l [1]byte
		if _, err = io.ReadFull(conn, l[:]); err == nil {
			_, err = io.CopyN(io.Discard, conn, int64(l[0])+2)
		}
	default:
		err = fmt.Errorf("invalid atyp %d", head[3])
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func socks5UserPass(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return fmt.Errorf("socks5 credentials too long")
	}
	req := []byte{0x01, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5 username/password auth failed")
	}
	return nil
}
