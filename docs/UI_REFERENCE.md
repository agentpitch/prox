# UI reference

This document describes the intended WebUI and tray behavior.

## 1. Global layout

The page is split into two columns:

- **left column**: configuration cards
- **right column**: observability cards

The right column is visually larger because runtime investigation requires more horizontal space.

The top bar is compact and scrolls with the page. It is not sticky.

## 2. Left column order

1. **Rules**
2. **Proxies**
3. **Chains**

A separate settings dialog is opened from the gear button near the `pitchProx` title.

## 3. Settings dialog

The settings dialog contains:

- Web UI listen address
- transparent listener port
- IPv4 listener
- IPv6 listener
- sniff bytes
- sniff timeout
- retention window in minutes

The retention window controls:

- active connection history window
- proxy activity chart window
- rule stats aggregation window

Settings are autosaved through `PUT /api/config`.

## 4. Rules card

### Rule list item

A rule list item shows:

- compact enable checkbox
- compact move-up / move-down buttons under the checkbox
- rule name
- action badge
- disabled badge when disabled
- summary chips derived from applications / hosts / ports / proxy / chain
- rule metrics for the retention window:
  - connection count
  - incoming bytes
  - outgoing bytes

Clicking the rule body opens the edit dialog.

Clicking any rule metric focuses observability on that rule.

### Rule edit dialog

Contains:

- name
- id
- action
- proxy selector
- chain selector
- enabled checkbox
- notes
- applications textarea
- target hosts textarea
- target ports input
- duplicate button
- delete button

Action-dependent behavior:

- `Direct` and `Block`: proxy and chain fields are disabled and cleared on save.
- `Proxy`: proxy field enabled, chain disabled.
- `Chain`: chain field enabled, proxy disabled.

## 5. Proxies card

Each proxy row shows:

- name
- status chips
- compact inline test target input
- `Проверить` button
- `Изменить` button
- `Удалить` button

The test status line:

- is empty before any test;
- shows centered `Проверка…` while running;
- shows the result after completion.

No overlapping controls are allowed.

## 6. Chains card

Each chain row shows:

- name
- enabled state
- proxy ID sequence summary
- edit/delete actions

The edit dialog must explain that proxy IDs are separated by `;`, comma or newline and that order matters.

## 7. Proxy activity card

Shows proxied traffic only.

### Chart semantics

- X axis: time inside the retention window
- Y axis: bytes per second
- two series:
  - incoming proxied bytes
  - outgoing proxied bytes

Summary numbers are shown in one compact line.

## 8. Active connections card

This area is optimized for rule investigation, not raw system traffic.

### Default view

The `Все` tab shows only connections that matched an explicit rule other than `Default`.

### Tabs

- `Все`
- `Proxy / Chain`
- `Direct`
- `Block`
- `Ещё`

`Ещё` means connections without an explicit non-default rule match.

### Additional filters

- free-text search input above the table filters rows by PID, process name/path, host, port, rule, action, state, proxy ID, and chain ID
- click on `Rule` cell to focus by rule
- click on `Action` cell to focus by action/process investigation

Rule focus and action tab filter are mutually exclusive. Selecting one clears the other. Search stays active as an additional local narrowing filter for the table.

### Table behavior

- rows are grouped by PID/process/host/port/rule/action;
- duplicate rows collapse into one row with a repetition counter;
- updates arrive by snapshot polling, not every single packet;
- history remains visible for the retention window.

### Copy behavior

The following fields should be copyable:

- PID
- process path
- host
- port

Hover over process shows the full executable path as tooltip.

## 9. Log card

The log is intended for investigation, not for raw packet spam.

Behavior:

- live updates come from SSE `/api/events`;
- newest lines appear first;
- the log stores up to 100 latest entries per process plus a generic global tail;
- clicking process/rule/action related filters changes the visible log subset;
- the log can be reset back to unfiltered state.

## 10. Tray icon

### Desktop mode only

The tray exists only in desktop mode.

### Visual behavior

The tray icon is a miniature filled graph:

- one color for incoming proxied traffic;
- another color for outgoing proxied traffic;
- if one series is higher, that series is rendered in the background.

### Interaction

- double click: open WebUI in the default browser
- right click: context menu
  - `Управление`
  - `Disable WebUI` / `Отключить WebUI` when WebUI is currently running
  - `Выйти`

`Disable WebUI` / `Отключить WebUI` disables static WebUI pages, configuration API, snapshots, and SSE streams while keeping the lightweight health/tray/control endpoints available. This lets both desktop tray and standalone `tray --url` mode re-enable WebUI on double click.

`Выйти` stops the whole desktop runtime, not only the tray icon.
