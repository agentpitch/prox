# WebUI reference

This document describes the intended WebUI behavior from v0.43 onward.

## 1. Application shell

The WebUI uses a persistent application shell:

- fixed left sidebar;
- sticky page header;
- one mounted page per primary domain;
- hash routes (`#/rules`, `#/monitor`, `#/proxies`, `#/chains`, `#/dropped`, `#/logs`);
- settings remain a modal because they affect the whole runtime.

The available navigation entries reflect real pitchProx domains. The UI does not present Applications, Hosts, Ports, DNS profiles, users, notifications, or reports as independent entities while the backend has no corresponding model.

The sidebar can collapse on desktop and becomes an overlay on narrow screens. The system card reports the real service state and build version returned by `/api/health`.

## 2. Rules page

Rules are shown in routing order in a dense table. The saved order is semantic: the first matching enabled rule wins.

Columns:

- page selection;
- enabled toggle;
- global routing order;
- name and comment;
- Applications;
- Target hosts;
- Ports;
- route/action;
- bounded recent activity;
- row actions.

Applications, Target hosts, and Ports remain raw strings in the configuration. Chips and abbreviated cell values are derived previews only. The WebUI must never convert those fields to arrays as the source of truth.

The full multi-value syntax remains supported:

- semicolon, comma, CR/LF separators;
- quoted values containing separators;
- multiple applications, hosts, ports, and ranges inside one rule;
- wildcards, PID, full application paths, CIDR, IP ranges, and port ranges.

Cells show the first values plus `+N`; their tooltip contains the full parsed list. Saving an otherwise unchanged rule preserves the raw text, apart from backend outer trimming.

### Search and filters

Rule search is local and case-insensitive. Whitespace-separated terms use AND semantics; quoted search phrases are supported.

The search index contains:

- name and stable ID;
- comment (`notes`);
- every application, host, and port value;
- action;
- proxy/chain ID and display name.

The index is rebuilt from the current config and never appended indefinitely.

Filters cover enabled, disabled, Proxy, Chain, Direct, and Block rules. Changing search, filter, or page size returns to page 1.

### Pagination and selection

Page sizes are 25 and 50. Only the current page is mounted in the DOM.

Every derived row retains:

- stable rule ID;
- original global index.

All mutations resolve the ID again against the latest in-memory config. Page indexes and filtered row indexes are never used as mutation identities.

Selection is stored in a bounded `Set` of rule IDs. The header checkbox selects the current page. After a complete page is selected, the selection banner can explicitly extend selection to every filtered result.

### Reordering

Move buttons display and modify the global routing order. Reordering is disabled while search or a non-default filter is active, because hidden rules would make the resulting priority ambiguous.

### Bulk operations

Bulk enable, disable, and delete produce one cloned config and one `PUT /api/config`, regardless of the number of selected rules. This bounds validation, disk writes, rule compilation, and any required runtime transition to one operation.

Only one config save may be in flight from a WebUI tab. Controls are disabled during the save and the previous state remains visible if the backend rejects the candidate.

## 3. Rule editor

The editor contains:

- name;
- enabled state;
- multiline comment/purpose saved in the existing `notes` field;
- Applications textarea;
- Target hosts textarea;
- Target ports textarea;
- action and proxy/chain selectors;
- stable ID under an advanced disclosure;
- duplicate and delete actions for existing rules.

The three matching fields remain textareas so users can keep one rule with multiple apps, hosts, ports, and ranges.

Client-side analysis reports:

- unclosed quotes;
- redundant `Any`/`*` mixed with narrower values;
- duplicate rule ID;
- up to three possible criteria overlaps.

Similarity is advisory. It compares normalized values and does not claim full glob/CIDR/range subsumption.

Closing a dirty editor requires confirmation. Save is single-flight. An existing rule is located by its original stable ID at save time rather than by a stale array index.

## 4. Rules import and export

Import and export are client-side rules-only operations. They never export proxy profiles, usernames, or passwords.

Format:

```json
{
  "format": "pitchprox.rules",
  "version": 1,
  "exported_at": "2026-08-03T12:00:00Z",
  "rules": []
}
```

Import accepts the versioned envelope, a full config containing `rules`, or a bare rules array. The preview reports invalid records, ID conflicts, exact criteria matches, and unresolved proxy/chain references.

ID conflict strategies:

- skip;
- replace in place;
- copy with a unique imported ID.

New rules keep their relative order and are inserted before an existing rule with ID `default`. Rules referencing a missing or disabled route can be imported disabled. The final result is applied with one config PUT.

## 5. Rule activity

`GET /api/rules/activity` supplies real bounded time series for the visible page only.

Frontend limits:

- at most the visible 50 rule IDs;
- 40 requested points;
- at most a 15-minute window, further limited by configured retention;
- one request at a time;
- sequential polling every 60 seconds;
- no polling while the page or browser tab is hidden;
- request cancellation when leaving Rules.

Backend limits:

- at most 50 unique IDs;
- 2–60 points;
- 1–60 minutes;
- memory `O(ids × points)`;
- no persistent cache, goroutine, or timer;
- streaming scan of the existing bounded hourly JSONL rule segments.

Direct traffic bytes are not always observable. The table therefore treats byte totals as recorded relay traffic and presents connection rate separately.

## 6. Other pages

### Monitoring

Shows the proxied traffic chart and active-connections investigation table. It uses the existing snapshot and focus behavior.

### Proxies and Chains

Keep the existing editors and proxy test behavior inside dedicated pages.

### Dropped

Uses a dedicated page with server-side search, paging, bounded file-size metadata, and selective deletion.

### Journal

Shows the existing live log. Journal uses one SSE connection plus a bounded
history backfill when that connection opens or reconnects; it does not run the
Monitoring snapshot timer. Monitoring uses sequential snapshots without log
payloads and does not open SSE.

## 7. Resource lifecycle

The routed UI must remain quiet when configuration pages are open:

- one EventSource and one sequential snapshot timer at most;
- live monitoring only on Monitoring or Journal;
- one sequential rule-activity timer only on Rules;
- page-specific timers and requests are cancelled on route changes and tab hiding;
- the shared shell remains mounted, while hidden pages release timers, requests, retained data, and heavy DOM content;
- rules use one delegated table listener rather than handlers per row;
- rule selection and activity maps are replaced/pruned, not appended indefinitely;
- export Blob URLs are revoked;
- import file inputs are cleared immediately after reading;
- no application-icon cache is introduced.

## 8. Responsive behavior

- Desktop: full sidebar and all selected table columns.
- Medium width: horizontal table scrolling and optional hidden columns.
- Mobile: sidebar overlay and each rule row becomes a compact grid card while preserving every action.

Users can hide Applications, Hosts, Ports, or Activity columns. Column choices, density, page size, and sidebar state are stored locally; rule search and filters are session-scoped.

## 9. Keyboard and accessibility

- `/` opens Rules and focuses search when the user is not typing.
- `Ctrl+N` / `Cmd+N` opens a new rule.
- `Escape` clears rule search.
- Rule names can open the editor with Enter or Space.
- Selection and enabled state use native checkboxes.
- Dialogs require an explicit accessible title and preserve native Escape behavior with dirty-state confirmation.

## 10. Tray behavior

Tray behavior is unchanged:

- double click opens WebUI;
- the context menu controls WebUI and process shutdown;
- the tray reads the lightweight traffic view;
- disabling WebUI keeps health/tray/control endpoints available.
