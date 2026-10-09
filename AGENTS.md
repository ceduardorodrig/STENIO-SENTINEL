---
tags: [meta, agents, governance, rust, engine]
---

# AGENTS.md — StenioSentinel Engine Governance Rules

This directory contains **StenioSentinel (Rust Engine v4.0.0)**, the universal static verification, architectural enforcement, and health monitoring engine for the entire ecosystem.

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
- A service may declare the documented exception for **distroless** images instead of a healthcheck: `labels: {homelab.healthcheck: watchdog}` (covered by an external watchdog — see `scripts/dns-watchdog`).

## DRY engine coverage (`ARCH-DRY-DUPLICATION`, v4.1 — 2026-10-09)

The DRY engine runs in **two layers** and grades severity (it never silences):

- **Line/token layer** (`src/dry.rs`) — every eligible language (`rs, ts, tsx, js, jsx, py, sh, css`): stable **FNV-1a** window hashing (replacing the non-stable `DefaultHasher`). A block made only of **declarative** lines (struct-field initializers / bare field shorthand) is **not reported**; a block that is **≥50% logic** is an `Error`, otherwise a `Warning`.
- **AST layer** (`src/dry_ast.rs`, Rust only) — `syn` fingerprints each statement subtree **formatting-invariantly** (identifiers/literals preserved for precision) and reports identical units shared by two or more files. Emitted as **`Warning` during rollout**; promote to `Error` after a fleet audit with zero false positives.

`run_quality_gate` blocks **only** on `Error` DRY findings; `Warning` findings are counted and surfaced without rejecting delivery.

See the vault runbook [`../stenio-troubleshooting.md`](../stenio-troubleshooting.md) §6 for the "single emission point" remediation recipe and the multi-language (Fase 4) decision.
