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

Cells show only the first configured values plus `+N`; no synthetic application symbol is rendered. Their tooltip contains the full parsed list. Saving an otherwise unchanged rule preserves the raw text, apart from backend outer trimming. The table has one intentionally compact density and no density preference.

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

- name and the enabled-state control on one non-wrapping row;
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
- redundant `Any` mixed with narrower values, plus the Applications-only `*`
  alias; a Target-host `*` remains a hostname wildcard rather than `Any`;
- duplicate rule ID;
- up to three possible criteria overlaps.

Similarity is advisory. It compares normalized values and does not claim full glob/CIDR/range subsumption.

Closing a dirty editor requires confirmation. Save is single-flight. An existing rule is located by its original stable ID at save time rather than by a stale array index.

For an existing rule, **Фактические срабатывания условий** is the first editor
section and is expanded immediately. This makes the saved rule's real behavior
visible before its editable fields. A new unsaved rule omits the section because
it has no stable history identity. Opening an existing editor starts one lazy
request (the row's **Детали условий** action opens the same view). Unsaved editor
text is not included; because history is keyed by stable rule ID, the selected
window can still contain the previous saved revision of that ID.

`GET /api/rules/condition-activity?id=<exact-id>&window_minutes=<1..60>&limit=20` supplies two complementary views without constructing the Applications × Hosts × Ports cross-product:

- top observed `application › host : port` tuples with hit count, share, last-seen time, and localized source counts;
- marginal coverage for every raw Applications, Hosts, and Ports token from the saved rule.

For each marginal dimension, an absent token is shown as zero observed hits only when the backend marks that dimension complete. If its bounded aggregation is truncated, the UI says that the token did not enter the observed sample and never invents a zero. The backend accuracy notice remains visible because sampled Direct observation can make even a complete marginal scan incomplete evidence of real use. Loading, empty, partial, and error states are explicit. The request is aborted and the result DOM is released when the editor closes; no condition-detail polling or client cache is used.

`unattributed_hits` is shown separately as a subset of **Прочие связки**, so bounded backend overflow is visible without double-counting totals. Malformed tuples or marginal values are discarded defensively and force a partial/truncated presentation; the frontend never invents `Any` for a missing tuple axis.

## 4. Rules import and export

Import and export are client-side rules-only operations. They never export proxy profiles, usernames, or passwords.

Both toolbar buttons open a transfer dialog instead of immediately opening or downloading a file:

- **Export** shows the complete versioned JSON in a read-only textarea. The primary action copies the entire payload to the clipboard; the left footer action downloads the same bytes as `pitchprox-rules-YYYY-MM-DD.json`.
- **Import** focuses an empty textarea for `Ctrl+V`. The left footer action loads a `.json` file into the same textarea, and **Check rules** sends either source through the same bounded parser and existing preview.

The preview is still mandatory before configuration changes. It reports structurally correct and skipped structurally damaged records, ID conflicts, exact matches, and unresolved routes. Backend compilation then performs the final criteria-syntax check atomically, so a rejected set does not partially change the configuration. A partially damaged set uses an explicit **Import correct** action. New configurations cannot grow beyond 2,000 rules; a legacy configuration already above that limit may still replace or skip rules as long as the operation does not increase its count. Clipboard text and files share the 5 MiB input limit, accept an optional UTF-8 BOM, and preserve raw multi-application, multi-host, and multi-port strings. Before saving, the client also checks the complete UTF-8 config body against the backend's 8 MiB request limit.

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

The per-rule condition drill-down counts observed TCP-соединения/срабатывания, not HTTP requests. Its response is bounded to 20 top tuples and 512 transient marginal labels per dimension on the backend; the frontend renders at most 100 authored tokens per dimension.

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

### Settings and application versions

Settings includes an **Обновление приложения** section. It does not issue a
network request on open: **Проверить обновления** explicitly requests GitHub,
reports whether a newer stable release exists, and renders at most five latest
published versions. The installed version is disabled as **Установлена**;
compatible newer, prerelease, and older versions can be selected.

A downgrade requires confirmation. A pre-manifest legacy version adds a second
warning that its built-in updater will disappear after the transition. Install
is disabled while settings have unsaved changes. During an accepted install the
dialog shows bounded download progress and polls only transaction status. The
old WebUI may briefly disappear while the exact process or service is replaced;
the page then recognizes the verified new build. Legacy success falls back to
the old `{ok:true}` health response and clearly states that further automatic
updates are unavailable.

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
- import file inputs are cleared immediately after selection; competing file reads use a generation token, and manual textarea input invalidates an unfinished read so pasted text cannot be overwritten;
- transfer textarea values and handlers are cleared when the dialog closes, and no clipboard payload is stored or cached;
- no application-icon cache is introduced;
- pending route callbacks, bounded toasts, config reads, editor condition reads, and view-specific animation frames are cancelled or released on their lifecycle boundary.
- update discovery has no timer or startup request; its five-item result,
  abort controllers, and install-status timer are released when Settings closes.

After one hour without a browser request, the backend automatically pauses only
the WebUI. It uses one reschedulable timer rather than a polling loop. A loaded
page schedules one check for the advertised `idle_deadline_at`; SSE pages also
receive the `webui_status` transition. On auto-pause the page must stop all
timers, requests, retries and EventSource activity, retain a persistent notice
that proxy routing continues, and explain that WebUI can be reopened from the
tray. It must not silently treat this state as a full service pause.

Every browser API call carries `X-PitchProx-WebUI: 1`; EventSource uses
`/api/events?_ui=1`. A `503` from an ordinary API triggers one read of the
still-available WebUI control status. Auto-pause and manual WebUI disable share
the persistent banner, but a full service pause remains a separate state and
never claims that proxy routing continues. No automatic retry runs after WebUI
has paused; the banner offers only a manual status recheck after the user acts
through the tray.

## 8. Responsive behavior

- Desktop: full sidebar and all selected table columns.
- Medium width: horizontal table scrolling and optional hidden columns.
- Mobile: sidebar overlay and each rule row becomes a compact grid card while preserving every action.

Users can hide Applications, Hosts, Ports, or Activity columns. Column choices, page size, and sidebar state are stored locally; rule search and filters are session-scoped.

## 9. Keyboard and accessibility

- `/` opens Rules and focuses search when the user is not typing.
- `Ctrl+N` / `Cmd+N` opens a new rule.
- `Escape` clears rule search.
- Rule names can open the editor with Enter or Space.
- Selection and enabled state use native checkboxes.
- Dialogs require an explicit accessible title and preserve native Escape behavior with dirty-state confirmation.

## 10. Tray behavior

- Double click and **Управление** enable WebUI when necessary and open it in the browser.
- While the service is active, the context menu shows **Приостановить работу** and exactly one WebUI toggle: **Отключить WebUI** while enabled or **Включить WebUI** while disabled/idle-paused.
- **Включить WebUI** only enables the interface; it does not open a browser. Proxy routing continues throughout a WebUI-only pause.
- A fully paused service shows **Запустить** instead of the WebUI toggle, because routing is paused too.
- The tray reads the lightweight traffic view, and disabling WebUI keeps health/tray/control endpoints available.
