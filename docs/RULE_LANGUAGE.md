# Rule language

This document defines the exact syntax and semantics of the rule fields.

## 1. General tokenization

The following separators are accepted in text fields:

- semicolon `;`
- comma `,`
- newline `\n`
- carriage-return newline `\r\n`

Separators are ignored while inside double quotes.

Examples that all split into the same tokens:

```text
chrome.exe; firefox.exe
chrome.exe, firefox.exe
chrome.exe
firefox.exe
```

Quotes are removed after tokenization.

```text
"C:\Program Files\JetBrains\*"
"quoted,value"
```

If a quote is opened and not closed, parsing fails with `unclosed quote`.

## 2. Applications

### Matching target

If a token contains a drive letter or a backslash, it is treated as a **full path pattern**.
Otherwise it is treated as a **basename pattern** and compared with the executable file name only.

Examples:

- `firefox.exe` → basename match
- `fire*.exe` → basename wildcard match
- `"*.bin"` → basename wildcard match
- `"C:\Program Files\JetBrains\*"` → full-path wildcard match

### PID syntax

If a token is made only of digits and is greater than zero, it is treated as a PID matcher.

Example:

```text
12345
```

A PID token matches only when the runtime was able to resolve the owner PID for the flow.

### Any syntax

`Any` and `*` both mean “match any application”.

## 3. Target hosts

Supported forms:

- `Any`
- exact host name — `github.com`
- wildcard host name — `*.example.com`
- exact IP — `8.8.8.8`
- IP wildcard — `192.168.1.*`
- CIDR — `10.0.0.0/8`
- IP range — `10.1.0.0-10.5.255.255`
- `%ComputerName%`

### Matching precedence

Host patterns are compiled in source order, but there is no internal precedence between host token types. A host field is considered matched if **any one host token** matches.

### `%ComputerName%`

This compares against the Windows computer name as provided by `os.Hostname()` and lowercased inside the compiled engine.

## 4. Target ports

Supported forms:

- `Any`
- exact port — `443`
- range — `8000-9000`

Port ranges are normalized so `9000-8000` becomes `8000-9000`.

## 5. Wildcards

`*` matches zero or more characters.

`?` matches exactly one character.

Wildcards are case-insensitive.

Examples:

- `fire*.exe` matches `firefox.exe`, `fire64.exe`
- `*.bin` matches `helper.bin`
- `192.168.1.*` matches `192.168.1.44`

## 6. Matching rules

A rule matches when all three predicates are true:

1. application matches
2. host matches
3. port matches

If a field is `Any`, that predicate is considered true.

## 7. Ordered evaluation

Rules are checked from top to bottom.

- disabled rules are skipped;
- the first enabled matching rule wins;
- no further rules are evaluated after the first match.

## 8. Examples

### Example A — local bypass

```text
Applications
"C:\Program Files\JetBrains\*"; "C:\Windsurf\*"; "C:\cursor\*"; firefox.exe

Target hosts
localhost; 127.0.0.1; %ComputerName%; ::1

Target ports
Any

Action
Direct
```

### Example B — vendor domains through one proxy

```text
Applications
*

Target hosts
www.jetbrains.com; resources.jetbrains.com; packages.jetbrains.team
content-autofill.googleapis.com
unleash.codeium.com; releases.codeiumdata.com; server.codeium.com
schemastore.org; www.schemastore.org; github.com
download.jetbrains.com
download-cdn.jetbrains.com
downloads.marketplace.jetbrains.com
plugins.jetbrains.com

Target ports
443

Action
Proxy
```

### Example C — PID pinning

```text
Applications
24512

Target hosts
Any

Target ports
Any

Action
Proxy
```
