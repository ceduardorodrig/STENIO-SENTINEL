# {{NAME}} Backlog

> **Active queue** of pending work. Method: `governance/backlog-method.md` (one queue, stable ids, mandatory origin, closed items move to [`backlog-archive.md`](backlog-archive.md)).

## Governance

| Rule | Description |
|---|---|
| **Single source** | Every open item has a `{{PREFIX}}nnn` id here; technical detail stays in the area doc (`Ref`). |
| **Active only** | ⏳ open, 🏗 in progress, ⏸ blocked. A closed item (✅ resolved, ✗ discarded) moves to the archive with its date. |
| **Mandatory origin** | Every item says when and how it appeared. |
| **Born open** | Nothing enters already resolved. |
| **Recurrence** | A closed problem that returns opens a new item with `Recurrence: {{PREFIX}}old`. |
| **Language** | English, except user-facing copy. |

Severity: 🔴 data/security/availability at risk · 🟠 relevant risk or blocking decision · 🟡 debt or improvement · 🟢 housekeeping.

## Items

| ID | Item | Ref | Sev | State | Origin | Recurrence |
|---|---|---|---|---|---|---|

## References

- [`backlog-archive.md`](backlog-archive.md): closed items
