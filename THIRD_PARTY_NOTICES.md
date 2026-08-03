# Third-party notices

This notice covers third-party components distributed with or compiled into the
pitchProx Windows package. It does not grant a license to pitchProx itself.

## WinDivert 2.2.2

pitchProx dynamically loads the official unmodified x64 WinDivert runtime:

- `WinDivert.dll`
- `WinDivert64.sys`

WinDivert is Copyright (C) 2019 Basil, and is dual-licensed under the GNU Lesser
General Public License version 3 or the GNU General Public License version 2, at
the recipient's option. The complete upstream license is included in the release
package as `WinDivert-LICENSE.txt`.

Upstream project and corresponding source:

- https://github.com/basil00/WinDivert
- https://github.com/basil00/WinDivert/releases/tag/v2.2.2

Local release-candidate packaging verifies the existing x64 runtime files and
the tracked verbatim license by SHA-256. CI additionally downloads and verifies
the exact official upstream archive before packaging its runtime files.

## Go toolchain and standard library

The executable contains the Go runtime and standard-library code from Go 1.26.5.
The Go license shipped with the exact build toolchain is included in the release
package as `Go-LICENSE.txt`.

Upstream project and source:

- https://go.dev/
- https://go.googlesource.com/go

## golang.org/x/sys

The executable uses `golang.org/x/sys` at the version pinned in `go.mod` and
`go.sum`. Its license is included in the release package as
`golang.org-x-sys-LICENSE.txt`.

Upstream project and source:

- https://pkg.go.dev/golang.org/x/sys
- https://go.googlesource.com/sys
