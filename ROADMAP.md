---
tags: [meta, governance, roadmap, canon]
---

# 🗺️ StenioSentinel Roadmap: Full English Native Engine (v4.0.0)

> **Target Version:** `v4.0.0` (Major Release)  
> **Language Tier:** Tier A (Public Open Source) — see [language-policy.md](../language-policy.md)  
> **Status:** Planned / Approved (Phase 0 Foundations Active)

---

## 🎯 Executive Objective

Transition the entire **StenioSentinel** codebase, CLI outputs, rule descriptions, diagnostic reports, and internal comments into **100% native idiomatic English**.

This cements StenioSentinel as an international, public-grade Rust static verification engine and architectural quality gate suitable for any OSS repository or enterprise pipeline without linguistic friction.

---

## 🛡️ Critical Invariant: Anti-Tampering (`src/guardian.rs`)

The `src/guardian.rs` subsystem enforces cryptographic and structural integrity across critical modules (`rule.rs`, `dry.rs`, `gov.rs`, `engine.rs`, etc.).
- **Hard Rule:** Any changes to rule strings, identifiers, or function signatures in critical modules **MUST** be synchronized with `critical_modules` in `src/guardian.rs` in the exact same atomic commit.
- Never translate strings in `rule.rs` without updating the Guardian baseline.

---

## 📐 Canonical Terminology Matrix (Glossary)

To ensure semantic consistency across all subcommands, rules, and reports:

| Portuguese Source Term | Canonical English Target | Primary Modules |
|:---|:---|:---|
| *Porteiro das Portas* | **Port Gatekeeper / Attack Surface** | `ports.rs` |
| *Raio-X de Infraestrutura* | **Infrastructure Health Snapshot** | `health.rs` |
| *Duplicação de Código (DRY)* | **Code Duplication (DRY Principle)** | `rule.rs`, `dry.rs` |
| *Erros impeditivos* | **Blocking Errors** | `main.rs` (Gate) |
| *Zero artefatos residuais* | **Zero leftover test artifacts** | `main.rs`, `gov.rs` |
| *EM REPOUSO / OFFLINE* | **IDLE / OFFLINE** | `ports.rs` |
| *PORTA ÓRFÃ NÃO CATALOGADA* | **UNCATALOGED ORPHAN PORT** | `ports.rs` |
| *BIND 0.0.0.0 NÃO AUTORIZADO* | **UNAUTHORIZED BIND 0.0.0.0** | `ports.rs` |
| *Isolamento de Escopo* | **Monorepo Scope Isolation** | `rule.rs`, `engine.rs` |
| *Soja / Stubs de IA* | **Lazy AI Stubs & Placeholders** | `rule.rs` |
| *Autoproteção Criptográfica* | **Cryptographic Anti-Tampering Protection** | `guardian.rs` |
| *Sub-rotinas / Gatilhos* | **Routines / Triggers** | `deploy.rs`, `remote.rs` |
| *Arquivos auditados* | **Audited files** | `main.rs` |

---

## 🚀 Execution Phases

### Phase 0: Foundations & Governance (Active)
- [x] Canonical terminology dictionary established.
- [x] Roadmap documented in `ROADMAP.md` and referenced in `AGENTS.md`.
- [x] Language policy compliance verified (Tier A).

### Phase 1: Core Rules & Rule Explanations (`v3.9.0-alpha`)
- [x] Translate all 52 rule names, summaries, descriptions, and suggestions in `src/rule.rs`.
- [x] Translate all rule explanations, examples, and remediation steps in `src/explain.rs`.
- [x] Update `src/dry.rs` violation messages.
- [x] Synchronize `src/guardian.rs` baseline strings atomically.
- [x] **Verification Gate:** `cargo test` + `stenio --self-test` (64/64) + `stenio --guardian`.

### Phase 2: Quality Gate & Core CLI Output (`v3.9.0-beta`)
- [x] Translate terminal banners and verdicts in `src/main.rs` and `src/baseline.rs`:
  - `[GATE APROVADO]` → `[GATE PASSED: Full Architectural Compliance]`
  - `[GATE REJEITADO]` → `[GATE FAILED: Blocking Errors Detected]`
- [x] Translate scan summaries (`Arquivos escaneados` → `Scanned files`).
- [x] **Verification Gate:** `cargo test` + `stenio --gate`.

### Phase 3: Specialized Domain Modules (`v3.9.0-rc`)
- [ ] Translate `src/ports.rs` (Network ASM output).
- [ ] Translate `src/health.rs` (Hardware, GPU, disks, Docker health).
- [ ] Translate `src/gov.rs` (Governance and test artifact audits).
- [ ] Translate `src/doc.rs` (Markdown link and structure validation).
- [ ] Translate `src/clean.rs` (Cache and docker hygiene).
- [ ] Translate `src/remote.rs` (SSH and Tailscale remote probes).

### Phase 4: Final Polish & Major Release (`v4.0.0`)
- [ ] Translate remaining internal source comments and docstrings.
- [ ] Verify clean compilation under `RUSTFLAGS="-D warnings"`.
- [ ] Full ecosystem regression check across all active workspaces.
- [ ] Tag and publish release `v4.0.0`.
