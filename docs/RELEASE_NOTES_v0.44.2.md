# pitchProx v0.44.2

This release removes a fixed 32 MiB cryptographic buffer from the background
process while preserving verified HTTPS updates and agent CLI control.

## Lower resident-process overhead

The updater introduced in v0.43 linked Go's HTTP and cryptographic implementation.
With Go 1.26, those dependencies include a 32 MiB static FIPS entropy buffer,
even when no update check is running. Garbage collection cannot reclaim this
static reservation.

- HTTPS downloads now use Windows WinHTTP and the operating system's certificate
  validation, with TLS 1.2 or newer. Redirects remain bounded and restricted to
  approved update hosts; HTTPS cannot downgrade to HTTP.
- SHA-256 verification and transaction tokens use Windows CNG. Digest, manifest,
  size, executable architecture, transaction ownership and rollback checks are
  retained. Native cryptographic errors fail the operation.
- CLI and update-helper health checks use a bounded loopback-only HTTP client,
  without importing another TLS stack. CLI writes are never automatically
  repeated, and redirects are refused.
- Native requests stream downloads, respect cancellation and deadlines, and
  close their handles and buffers when finished.
- Builds reject the heavy production dependencies and writable static sections
  above 2 MiB. Build manifests include the checked memory layout.

A controlled 60-second comparison on one Windows host, with the same Go 1.26.8
compiler and isolated Direct-only configurations, reduced private committed
memory from approximately 49 MiB to 16.4 MiB. Neither process had an open UI,
tray or WinDivert interception; neither measurement forced garbage collection
or working-set trimming. Active routing, connections and native Windows caches
add workload-dependent memory. This is a measured baseline improvement, not a
promise that every installation uses the same amount of RAM.

## Compatibility

Configuration, rules, history, CLI protocol and update artifact formats are
unchanged. The supported Windows build keeps Go 1.26.8 and the verified
WinDivert 2.2.2 runtime; no custom cryptographic algorithm, modified Go runtime
or older compiler is used.

The updater supports explicit HTTP proxy endpoints through HTTPS_PROXY or
HTTP_PROXY (including their lowercase forms) and honors NO_PROXY. Automatic
proxy discovery is not enabled. Proxy URLs using other schemes or embedded
credentials are rejected with a clear error instead of silently bypassed.
This restriction concerns the updater's own environment-based proxy setting;
configured application routing through Proxy/Chain is unchanged.

v0.44.1 can discover and install this release using its release-assets fallback.
An installed v0.43 may still need a manual EXE replacement if GitHub omits assets
from its release-list response. The local configuration is preserved.
