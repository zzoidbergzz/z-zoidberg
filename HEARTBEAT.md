# HEARTBEAT.md

**Empty file = HEARTBEAT_OK.** No action needed.

When this file contains only its header and this explanation, the heartbeat
poller should skip all API calls and exit 0. Add items only when a specific
check is due; remove them once done.

---

## Rotation state

Heartbeat state (last-run timestamps, cadence counters) lives in
`memory/heartbeat-state.json`, **not** in this file. Pollers must read/write
that JSON file directly and must NOT block on HEARTBEAT.md being non-empty.

---

## Quiet hours

No non-urgent outbound actions between **23:00–08:00 UTC**.
Urgent = a security alert or paging-level incident; everything else waits.

---

## Example checklist (not active — for reference only)

When a check needs to run, append items like the block below, run the check,
then either mark done (`[x]`) or remove the line once resolved.

```markdown
- [ ] email: unread count, flag anything from known alert senders
- [ ] calendar: next 24 h events, surface conflicts
- [ ] weather: current conditions + severe warnings for home location
- [ ] security feeds: new CVEs matching watchlist keywords
- [ ] todo backlog: overdue items in TODO.md / session todos
```

---

## How to add a check

1. **Append** one `- [ ] <check-name>: <description>` line to this file.
2. **Run** the check (poller reads this file, performs the action, writes result
   to `memory/heartbeat-state.json`).
3. **Mark done** (`- [x]`) or remove the line. Leave the file empty (header
   only) when all checks are resolved.
