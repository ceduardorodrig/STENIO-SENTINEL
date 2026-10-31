---
tags: [meta, agents, governance, rust, engine]
---

# AGENTS.md — StenioSentinel Engine Governance Rules

This directory contains **StenioSentinel (Rust Engine v4.6.0)**, the universal static verification, architectural enforcement, and health monitoring engine for the entire ecosystem.

When modifying any file in this repository, follow these mandatory governance rules:

**Language Tier:** A (Public OSS) — see [language-policy.md](../language-policy.md). All logs, CLI strings, documentation, and comments MUST be in English. As of v4.0.0, the engine is 100% native English (see [ROADMAP.md](ROADMAP.md)).

## 🦀 Rust Sovereignty & Architectural Laws

1. **PURE NATIVE RUST (RUST 2024):** All engine code must remain in high-performance native compiled Rust (`edition = "2024"`). Zero runtime Python dependencies (`ARCH-NO-PYTHON`).

2. **PROHIBITION OF UNWRAP/EXPECT IN PRODUCTION (`RUST-NO-UNWRAP`):**
   - In production code, both `.unwrap()` and `.expect()` cause unconditional runtime panics.
   - Replacing `.unwrap()` with `.expect()` is categorized as a bypass attempt and blocked.
   - All errors must be handled with `?`, `match`, or safe fallbacks (`unwrap_or_default()`).

3. **SCOPE ISOLATION (`ARCH-SCOPE-ISOLATION`):**
   - The engine architecture is strictly isolated. AI models are strictly prohibited from altering governance rules or engine internals to make tests pass during product work.

4. **SUB-MILLISECOND PERFORMANCE TARGET:**
   - Single-file checks must complete in under 5ms. Full ecosystem scans must execute in under 500ms using `rayon` multi-threading and regex pre-compilation.

5. **MANDATORY QUALITY GATE VERIFICATION (RULE 0):**
   - Always run `cargo check`, `cargo test`, and `stenio --diff` before concluding any turn.

## Context-aware rules (2026-10-07)

A `Rule` may declare an optional **context**, so a text pattern is not blindly applied to every file:

- `requires_pattern: Option<String>` — a second regex describing the context in which the rule keeps its **full severity** (e.g. a Rust file that is actually async: `async fn`, `.await`, `tokio::`, `async_std::`, `smol::`, `futures::`).
- `severity_without_requires: Option<Severity>` — severity used when the context does **not** match. `None` means "do not report"; `Some(Warning)` keeps the finding **visible** instead of dropping it silently (no silent gap).

Applied to **`RUST-ASYNC-SLEEP`**: `std::thread::sleep` is an **Error** in async code and only a **Warning** in synchronous code — so synchronous CLIs have a sanctioned path without `stenio-ignore` (which the homelab `AGENTS.md` forbids). The two fields are **engine-only**: they are *not* exposed in the `--learn` payload, so learned rules cannot carry artificial contexts.

> Residual, documented limitation: a **synchronous helper** (no async marker) called from async code stays a Warning rather than an Error — inherent to a per-file heuristic. Visibility is never lost.

## Compose hygiene coverage (`INFRA-COMPOSE-HEALTHCHECK`, 2026-10-07)

The `INFRA-COMPOSE-*` checks (YAML syntax, restart policy, **healthcheck presence**) live in `check_compose_file()` and are shared by `audit_infrastructure()` and `audit_compose_dir()`. The latter runs them over the **NAS mirror** of the hosts' composes (`/mnt/BACKUP/configs-homelab`), which the `homelab` scope merges into its infrastructure audit — the vault itself contains **no** compose files, so without the mirror the rules would never see a real service.

- The mirror scan skips `golden/` (duplicate copies) and only runs when the target is the **real vault layout** (an external `--path` does not drag the NAS in).
- `SEC-*` rules are deliberately **not** run on the mirror: it is captured content, not our authored tree.
- A service may declare the documented exception for **distroless** images instead of a healthcheck: `labels: {homelab.healthcheck: watchdog}` (covered by an external watchdog — the `dns-watchdog` crate in `MNEMOCINE-OPS/provisioning/`).

## DRY engine coverage (`ARCH-DRY-DUPLICATION`, v4.1 — 2026-10-09)

The DRY engine runs in **two layers** and grades severity (it never silences):

- **Line/token layer** (`src/dry.rs`) — every eligible language (`rs, ts, tsx, js, jsx, py, sh, css`): stable **FNV-1a** window hashing (replacing the non-stable `DefaultHasher`). A block made only of **declarative** lines (struct-field initializers / bare field shorthand) is **not reported**; a block that is **≥50% logic** is an `Error`, otherwise a `Warning`.
- **AST layer** (`src/dry_ast.rs`, Rust only) — `syn` fingerprints each statement subtree **formatting-invariantly** (identifiers/literals preserved for precision) and reports identical units shared by two or more files. Emitted as **`Warning` during rollout**; promote to `Error` after a fleet audit with zero false positives.

`run_quality_gate` blocks **only** on `Error` DRY findings; `Warning` findings are counted and surfaced without rejecting delivery.

See the vault runbook [`../stenio-troubleshooting.md`](../stenio-troubleshooting.md) §6 for the "single emission point" remediation recipe and the multi-language (Fase 4) decision.

## Backlog traceability coverage (`DOC-BACKLOG-*`, v4.4.0 — 2026-10-12)

`src/backlog.rs` cross-checks the homelab backlog against the per-document
`pending: [HB-xxx]` frontmatter field, in **both** directions — the same "drift by
cross-reference" pattern as `DOC-SERVICE-UNINDEXED`. Since v4.4.0 the backlog is **two files**:
the **active queue** (`mnemocine/backlog.md`, states `open`/`in progress`/`blocked`) and the
**history** (`mnemocine/backlog-archive.md`, `resolved`/`discarded` with a date). An id lives
in exactly one of them; a closed item leaves the document's `pending:` list.

- **`DOC-BACKLOG-DRIFT`** — a `Ref` points to a missing document, an **active** item's
  document does not declare it, or a document declares an id the queue lacks (or declares an
  **archived** id).
  **Adaptive severity**: the drift inherits the item's severity — 🔴 is an `Error` (blocks
  `run_quality_gate` and `--scope homelab`), everything else stays a `Warning`.
- **`HOMELAB-BACKLOG-MALFORMED`** — a row missing its `Ref`, carrying an unknown severity or an
  invalid state, or a table with no recognizable header (a header-less table is **not** a silent
  "zero items" pass).
- **`HOMELAB-BACKLOG-LIFECYCLE`** — a closed item (`resolved`/`discarded`) with no closing date
  (`YYYY-MM-DD`).
- **`HOMELAB-BACKLOG-STATE`** — an id in **both** files, or a state that does not match its file
  (a closed state in the queue, an active state in the archive).
- **`DOC-BACKLOG-RECURRENCE`** — a `Recurrence` / `Recurred-by` pair that does not agree (a
  recurring item must point at an *archived* item, and that archived item must point back).

The **columns are read from the table header**, so the layout can grow (e.g. the `Recurrence`
column) with no engine change. The audit is inert when the scope has no mnemocine tree or no
adopted index. Three IDs are pinned as Guardian anchors in `src/guardian.rs`
(`DOC-BACKLOG-DRIFT`, `HOMELAB-BACKLOG-MALFORMED`, `HOMELAB-BACKLOG-LIFECYCLE`), so deleting
them trips the tamper alert. CLI: `stenio --backlog` (queue) and
`stenio --backlog --search <term>` (queue + archive). Runbook:
`mnemocine/guides/backlog-routine.md`.

## Tools catalog discovery (`--tools`, 2026-10-12)

`--tools` no longer assumes a fixed `provisioning/` layout. The catalog
(`install-homelab-tools.sh`) is resolved by, in order: the **`STENIO_TOOLS_CATALOG`**
environment variable (installer path, or the tools root that contains `scripts/`),
then a **bounded (depth ≤ 4), gitignore-aware discovery** of the installer anywhere
in the tree. The tools root is derived from the installer's location (its `scripts/`
parent). This lets the operational tooling live in a dedicated repository
(`MNEMOCINE-OPS`) — or move again — **without an engine change**.

`src/tools.rs` carries **no Guardian anchors**, so the change is tamper-neutral
(verified with `stenio --guardian`: 13 modules, zero tampering).

## GPU unification coverage (`HOMELAB-GPU-UNIFIED`, v4.5.0 — 2026-10-12)

The RTX 5050 is a single, scarce device arbitrated by the `hl-infer` gateway (ADR-020, no
CPU fallback). Two independent audits now keep GPU work inside that gateway:

- **Static rule** (`src/infra.rs`) — `HOMELAB-GPU-UNIFIED`: a compose service that claims the
  GPU (`runtime: nvidia`, `gpus:`, `deploy` device reservations or `NVIDIA_VISIBLE_DEVICES`)
  must be a **registered consumer** of the gateway. It is emitted from `check_compose_file()`
  (the same single materialization point shared by `audit_infrastructure()` and
  `audit_compose_dir()`), so it also covers the NAS compose mirror. Severity is **Warning**
  during rollout — promote after a fleet audit with zero false positives.
- **Consumer allowlist is data, not code** — the fleet's known consumers live in
  `mnemocine/network/gpu-consumers.txt` (one per line, lowercase, `#` comments). The engine
  resolves it once per audit and falls back to a built-in list when the file is absent, so
  registering a new consumer is a **data edit** that never needs an engine change.
- **Live drift audit** (`src/gpu.rs`, surfaced through `--health`) — queries the gateway at
  `HL_INFER_URL` (default `http://127.0.0.1:9095`) for `/v1/ready`, `/v1/gpu/consumers` and
  `/v1/queue`, and reports who holds VRAM. Any process classified **`unmanaged`** (holding
  VRAM with no lease) becomes an audit error carrying its pid, name, MiB and a remediation
  pointer to `mnemocine/guides/gpu-centralization.md`. An absent gateway degrades to
  "at rest" and never fails the audit.

HTTP is reused from the existing Rust `xh` client via the shared
`crate::health::http_get_body` helper and parsed with the already-present `serde_json`; no new
dependency is introduced. `src/gpu.rs` and `src/infra.rs` carry **no new Guardian anchors**.

## Service naming coverage (`HOMELAB-NAMING-SERVICE`, v4.6.0 — 2026-10-13)

Every **Mnemocine infrastructure service** — a systemd unit (service or timer) — carries the
**`hl-`** prefix (canonized 2026-10-12; fleet migrated under HB-019). `src/infra.rs` enforces it
in `check_service_naming()`, called from the same systemd block that already runs
`INFRA-SYSTEMD-SYNTAX`, so a unit without the prefix is a `HOMELAB-NAMING-SERVICE` **Warning**
(rollout) wherever our own units are audited.

- **Exempt by design** (documented in `mnemocine/guides/ferramentas-de-operacao.md` § Service
  Naming Convention): template / instance units (`wol@<iface>`, `notify-backup-failure@<unit>`),
  SUMÆNIMÁ / Miracena products (`sae-*`, `sumaenima-*`, `miracena-*`) and host-tuning helpers
  (`tailscaled-wait`, `disable-acpi-spurious-wakeup`). The prefix lives on the **unit**, never on
  the binary — renaming is runtime-transparent to the executable and to port-based consumers.
- The check is gated by `code_debt`, so captured mirrors and upstream forks (whose units are not
  ours to rename) are never flagged, and `golden/` copies are skipped. The dynamic counterpart is
  `stenio --reconcile` (the service catalogue is the declaration it checks reality against).
- The live `MNEMOCINE-OPS/provisioning/systemd/` tree is clean: 70 `hl-*` units + the exempt
  `notify-backup-failure@.service`. `src/infra.rs` carries **no new Guardian anchors**.

## Port-view consistency (`HB-054`, v4.6.0 — 2026-10-13)

`health.rs::check_ports_health` no longer keeps a second, parallel port heuristic. It consumes the
`--ports` auditor's single source of truth — `ports::load_port_catalog()`,
`ports::load_port_exceptions()` (the §4 table parsed from `mnemocine/network/ports.md`) and
`ports::is_unauthorized_wildcard_bind()` — and only adds the two *uncatalogued* dispositions the
auditor renders inline (loopback, client/ephemeral range). The former hardcoded `2049`/`111`/
`20048` exemptions and the catalogue-text `tailscale0` heuristic are gone, so `--health` and
`--ports` can never disagree on the same live state.


## Backlog queues as data (`backlog-queues.toml`, 2026-10-30)

The canonical method is [`../backlog-method.md`](../backlog-method.md). `src/backlog.rs` audits **every queue declared in `backlog-queues.toml`** with one lifecycle model; the registry is embedded with `include_str!`, so the set of queues is versioned with the engine and reproducible from a clean build.

| Queue | Location | Prefix | Traced via `pending:` |
|---|---|---|---|
| Homelab | `mnemocine/backlog.md` | `HB-` | yes (bidirectional) |
| SUMÆNIMÁ Hub | `<hub>/docs/backlog.md` (needs `app/`) | `SB-` | no |
| Miracena engagement | `clients/miracena/backlog.md` | `MB-` | no |

- `audit_backlog()` audits the **linked** queues (homelab); `audit_product_queues()` audits the rest and is called from `audit_documentation()`, so it runs in the `hub`, `homelab` and `vault` scopes without duplicating messages.
- Product queues are checked for structure, lifecycle, state, recurrence and `Ref` resolution (`HOMELAB-BACKLOG-MALFORMED`, `-LIFECYCLE`, `-STATE`, `DOC-BACKLOG-RECURRENCE`, `DOC-BACKLOG-DRIFT`); the reverse document walk is skipped.
- Tables accept the English state words **or** the glyphs ⏳ 🏗 ⏸ ✅ ✗, the severities 🔴🟠🟡🟢🔵💡 and Portuguese header synonyms. Columns are resolved from the header.
- **CLI:** `stenio --backlog [--search <term>]` covers all queues found under `--path`; `stenio --backlog-new <PREFIX> --path <dir> [--backlog-name N]` scaffolds a queue from `templates/backlog*.md.tpl` (refuses to overwrite or to reuse a prefix).
- **Adding a queue:** scaffold it, append it to `backlog-queues.toml`, rebuild, run `stenio --guardian`. Tests guard the registry (parses, unique prefixes, only `HB-` linked) and the scaffolder (a fresh queue audits clean; never overwrites).
- Rule ids keep their `HOMELAB-` prefix for compatibility (Guardian anchors); they apply to every queue.
- Authorization: extending the engine was explicitly authorized by the owner on 2026-10-30 (`ARCH-SCOPE-ISOLATION` otherwise forbids engine edits during product work).
