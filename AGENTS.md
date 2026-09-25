---
tags: [meta, agents, governance, rust, engine]
---

# AGENTS.md — StenioSentinel Engine Governance Rules

This directory contains **StenioSentinel (Rust Engine v3.1.0)**, the universal static verification, architectural enforcement, and health monitoring engine for the entire ecosystem.

When modifying any file in this repository, follow these mandatory governance rules:

**Language Tier:** A (Public OSS) — see [language-policy.md](file:///mnt/NVME_PCI/agentic-ai/governance/language-policy.md). All logs, CLI strings, documentation, and comments MUST be in English.

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
