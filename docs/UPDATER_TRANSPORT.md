# Windows updater transport

The Windows executable uses WinHTTP and Schannel for HTTPS downloads. It does
not link a second Go TLS stack into the background proxy process. SHA-256 and
transaction randomness use Windows CNG; release digests, manifests, size limits
and the update handoff checks remain mandatory.

The downloader accepts TLS 1.2 or newer and uses the Windows certificate trust
store. It does not ignore certificate errors. Redirects are followed only after
the existing GitHub host allowlist has accepted the destination, with a bounded
redirect count and no HTTPS-to-HTTP downgrade. Responses are streamed in bounded
reads, and cancellation closes the native request before its buffers are freed.
The client deadline includes reading the body, including an unread response.
Request, connection and session handles are closed after every request; there
is no background polling, persistent client session or update connection pool.

## Explicit outbound proxies

The Windows updater honors `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, with the
lowercase forms used when the corresponding uppercase variable is empty.
Without an environment proxy it connects directly. It does not discover WPAD,
run a PAC script, or use an interactive user's browser proxy settings. Localhost
and loopback IP addresses bypass environment proxies.

Supported proxy values describe a plain HTTP forward proxy, for example
`HTTPS_PROXY=http://proxy.example:8080` or `HTTPS_PROXY=proxy.example:8080`.
An HTTPS download still uses TLS to the destination through the proxy's CONNECT
tunnel, with the same certificate checks. `NO_PROXY` supports comma-separated
hostnames, domains, IP addresses, CIDR ranges, optional ports, and `*`.

HTTPS-to-proxy and SOCKS proxy URLs, and proxy URLs containing credentials, are
not supported by this transport. A selected unsupported proxy produces an
explicit error; the updater does not silently connect directly or include the
proxy URL or password in that error. Windows integrated authentication and
automatic cookie handling are disabled. Use an unauthenticated HTTP forward
proxy, a matching `NO_PROXY` exception where direct access is intended, or the
manually downloaded release package in those environments.

## Native lifetime guarantees

WinHTTP operates asynchronously. Callback context is an integer token into a
Go-owned registry, not a retained Go pointer. A single callback is registered
for all requests; registry entries disappear at the final `HANDLE_CLOSING`
notification. Go buffers passed to native asynchronous reads remain pinned
until the completion callback or final handle close. API entry and handle close
are serialized so cancellation cannot race a synchronous API invocation.

References: [WinHTTP concurrency](https://learn.microsoft.com/en-us/windows/win32/winhttp/concurrency-in-winhttp),
[handle closing and final callbacks](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpclosehandle),
[async read buffer lifetime](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpreaddata).
