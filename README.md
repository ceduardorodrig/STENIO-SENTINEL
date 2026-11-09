# 🛡️ StenioSentinel (v4.14.0) — High-Performance AI Governance Engine in Rust

[![CI](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square&logo=githubactions)](https://github.com/ceduardorodrig/STENIO-SENTINEL)
[![Rust 2024](https://img.shields.io/badge/rust-edition%202024-orange?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](LICENSE)
[![Audit Speed](https://img.shields.io/badge/scan%20latency-%3C1ms%20to%20%3C200ms-purple?style=flat-square&logo=speedtest)](https://github.com/ceduardorodrig/STENIO-SENTINEL)
[![Quality Gate](https://img.shields.io/badge/rule%200-anti--bypass-red?style=flat-square&logo=securityscorecard)](https://github.com/ceduardorodrig/STENIO-SENTINEL)

> **"Sub-millisecond static governance engine, anti-bypass quality gate, and architectural integrity sentinel for AI coding agents written in Rust 2024."**

---

## 📑 Table of Contents

- 🎯 [Overview & Purpose](#-overview--purpose)
- 🧠 [The AI Coding Problem (Why StenioSentinel?)](#-the-ai-coding-problem-why-steniosentinel)
- ⚡ [Key Capabilities (v4.18.0 Superpowers)](#-key-capabilities)
- 📐 [Architecture Diagram](#-architecture-diagram)
- 🚀 [Installation & Quick Start](#-installation--quick-start)
- 🛠️ [CLI Command Reference](#️-cli-command-reference)
- 🔍 [Built-in Rule Catalog & Scopes](#-built-in-rule-catalog--scopes)
- 🗺️ [Roadmap (v4.0.0 Migration)](ROADMAP.md)
- 📜 [License](#-license)
- 📬 [Author & Community](#-author--community)

---

## 🎯 Overview & Purpose

**StenioSentinel** is a deterministic, ultra-fast static analysis engine, live container inspector, relational schema auditor, and architectural governance sentinel developed in pure **Rust 2024**. 

Built to pair with autonomous AI agents (Claude Code, Gemini CLI, Cursor, Codex, OpenCode, and local LLMs), StenioSentinel acts as an unyielding **Quality Gate (Rule 0)**. It enforces architectural sovereignty, catches silent bypasses, validates documentation integrity, prevents runtime panic risks, and eliminates code duplication — scanning thousands of files in under **10 to 200 milliseconds**.

---

## ⚡ Key Capabilities (v4.14.0 Superpowers)

### 1. Sub-Millisecond Multi-Threaded Engine
Leveraging Rayon and the memory-mapped `ignore` walker, StenioSentinel traverses directories concurrently while honoring `.gitignore` and Syncthing `.stignore` rules. Full audits complete in **1ms to 200ms**.

### 2. Knowledge Graph Engine (`--graph`, `--graph-orphans`)
Constructs a directed graph of all Markdown documents and cross-links via `petgraph`. Computes network density, cyclic clusters (Tarjan's SCC), top referenced knowledge hubs, unreferenced orphan notes, and exports Graphviz DOT topologies (`--graph-dot`).

### 3. Docker Live Drift Inspector (`--docker`)
Connects directly to the local Docker socket (`/var/run/docker.sock`) via `bollard` in **19ms**. Inspects container exit states (catches dead/exited containers with error codes) and alerts on insecure `0.0.0.0` wildcard port exposures vs. loopback/Tailscale binds.

### 4. Native MCP SSE Network Server (`--mcp-sse`)
Built on `axum` and `tokio`, exposes a local Model Context Protocol (MCP) server over Server-Sent Events (SSE) and JSON-RPC 2.0 (`/sse`, `/message`, `/health`). Allows OpenCode, Claude Code, and remote agents on the Tailnet to invoke all 10 Stenio tools remotely without personal API keys.

### 5. Local Offline Semantic Search (`--semantic`)
Pure Rust in-memory TF-IDF vectorizer and cosine similarity ranking (<250ms). Answers natural language queries over the entire vault/codebase offline, with zero external API calls, zero token costs, and zero cloud leaks.

### 6. Mandatory Quality Gate & Anti-Bypass (Rule 0)
Rule 0 enforces that no AI agent can claim task completion without passing Stênio's static verification. Unhandled unwraps, skipped tests, and suppressed linter flags are treated as critical blocking failures.

### 7. Interactive Didactic Remediation (`--explain`)
Whenever a rule violation occurs, agents and developers can execute:
```bash
stenio --explain <RULE_ID>
```
Stênio prints the rule's rationale, bad code examples, good code examples, and the exact remediation recipe.

### 8. Tailscale Mesh & Homelab Observability (`--mesh`, `--health`)
Performs concurrent asynchronous socket probes across distributed infrastructure nodes (Tailscale / WireGuard) in under **30ms to 100ms**, delivering instant health telemetry of NVMe storage, RAM, and GPU accelerators (NVIDIA RTX).
```bash
stenio --explain <RULE_ID>
```
Stênio prints the rule's rationale, bad code examples, good code examples, and the exact remediation recipe.

### 4. Surgical Auto-Fixing (`--fix`)
Fixes common formatting issues, tag discrepancies, and syntax divergences atomically on disk without manual intervention.

### 5. Tailscale Mesh & Homelab Observability (`--mesh`, `--health`)
Performs concurrent asynchronous socket probes across distributed infrastructure nodes (Tailscale / WireGuard) in under **30ms to 100ms**, delivering instant health telemetry of NVMe storage, RAM, and GPU accelerators (NVIDIA RTX).

---

## 📐 Architecture Diagram

```mermaid
flowchart TD
    subgraph INPUT ["📂 Workspaces & Targets"]
        CODE["Rust / TypeScript / Go Code"]
        DOCS["Markdown Docs & Vault Notes"]
        INFRA["Compose, Systemd, SOPS Envs"]
    end

    subgraph ENGINE ["🛡️ StenioSentinel Core (Rust 2024)"]
        direction TB
        PARSER["Rayon Multi-Threaded Scanner<br/>(ignores .stversions, target, gitignored)"]
        
        subgraph AUDITORS ["Parallel Audit Subsystems"]
            RUST_RULE["🦀 Rust Sovereignty & Unwraps"]
            DRY_RULE["🔄 DRY Token Hash Engine"]
            DOC_RULE["📑 Link & Disclaimer Sentinel"]
            GOV_RULE["⚖️ Agent Laws & Governance"]
            INFRA_RULE["🔒 SOPS & Port Sentinel"]
        end

        PARSER --> AUDITORS
    end

    subgraph GATE ["🚦 Quality Gate (Rule 0)"]
        DECISION{"Any Blocking Errors?"}
        AUDITORS --> DECISION
        DECISION -- "Yes (Violations Found)" --> FAIL["❌ Task Blocked<br/>Exit Code 1 + Didactic Suggestion"]
        DECISION -- "No (100% Clean)" --> PASS["✅ Quality Gate Approved<br/>Exit Code 0 (<20ms)"]
    end
```

---

## 🚀 Installation & Quick Start

### Build from Source (Cargo)

Ensure you have Rust 1.85+ installed (Rust 2024 edition compatible):

```bash
# Clone the repository
git clone https://github.com/ceduardorodrig/STENIO-SENTINEL.git
cd STENIO-SENTINEL

# Build optimized release binary
cargo build --release

# Install to user PATH
cp target/release/stenio ~/.cargo/bin/
```

### Quick Run

```bash
# Run contextual audit on current directory
stenio

# Audit specific directory or repository
stenio --path /path/to/project

# Run git diff staged audit (pre-commit hook)
stenio --diff

# Explain any rule
stenio --explain DOC-VIBE-DISCLAIMER
```

---

## 🛠️ CLI Command Reference

```text
StenioSentinel v4.14.0 — Universal AI Governance & Static Sentinel

Usage: stenio [OPTIONS]

Options:
      --path <PATH>          Target directory to scan [default: .]
      --scope <SCOPE>        Audit scope: [hub, homelab, vault, doc, cv, all]
      --rule <RULE_ID>       Execute only a specific rule by ID
      --diff [<REF>]         Audit only files modified relative to git ref (e.g., HEAD~1 or staged)
      --fix                  Apply automatic surgical repairs to violations
      --fast                 Fast mode (skip deep cross-linking and token hash checks)
      --clean                Sanitize debug artifacts, leftover test files, and reclaim disk
      --mesh                 Concurrent socket probe across Tailscale network nodes
      --health               Full-spectrum system diagnostic (NVMe, RAM, GPU, services)
      --graph                Audit knowledge graph topology (nodes, edges, hubs, density)
      --graph-orphans        List all unreferenced orphan documents in the vault
      --graph-dot            Export the vault knowledge graph in Graphviz DOT format
      --docker               Audit live Docker containers, failed services, and wildcard binds (bollard)
      --mcp-sse              Run Model Context Protocol HTTP Server-Sent Events daemon
      --mcp-host <HOST>      Host IP for MCP SSE server [default: 0.0.0.0]
      --mcp-port <PORT>      Port for MCP SSE server [default: 9099]
      --semantic <QUERY>     Local offline semantic search over vault documents (TF-IDF vectorizer)
      --top-k <N>            Number of top semantic matches to return [default: 5]
      --typegen              Generate TypeScript types from Rust DTO structs
      --explain <RULE_ID>    Explain why a rule exists with bad/good examples
      --self-test            Run built-in synthetic rule integrity tests
      --history              Also scan `git log -p --all` of --path for credential shapes (default off)
  -h, --help                 Print help
  -V, --version              Print version
```

---

### Frappe release flow (v4.15.0)

Configured by the `[frappe]` table of the app's `steniocheck.toml` (no project name in the engine; `--config <file>` overrides).

- `stenio --scope frappe [--path <app root>]`: every rule tagged `Frappe` in the rule table below (the count lives in the table, not in this sentence).
- `stenio pre-release --repo <app root> --tag vX [--prev vY] [--after-build] [--tagged]`: frappe, fork and custom-rule scopes in parallel, `__version__` = tag, tag unused (or at HEAD with `--tagged`), clean tree, HEAD = origin/main, FULL/TEXT-ONLY classification (fail-safe FULL), new msgids translated and cased, no credential shape in the diff, Dockerfile `APP_REF`, built image `.built-from`.
- `stenio --backlog --next-id <HB|SB|MB|GB>`: next free id counting the active file and the archive; `stenio backlog --fix` adds missing ids to the `pending:` frontmatter (DOC-BACKLOG-DRIFT) without touching other keys (v4.16.0). Since v4.18.0 the documented subcommand form (`stenio backlog --next-id GB`) defaults `--path` to the vault root found from the working directory (else the standard vault), so it works from any directory (GB-031).
- `stenio opportunity add --title '<RULE-ID>' --evidence ... --desired ... --acceptance ... [--origin 'agent, harness'] [--priority 🟠] [--ref <doc>] [--path <vault>] [--dry-run]`: the one command every agent uses to log a Stenio opportunity. Allocates the next `GB-` id and refuses a title that is already open; inserts the formatted row after the last `GB` row of `governance/backlog.md` (read, insert one line, guarded write; refused if the file changed meanwhile; no `.bak`), adds the id to `pending:` of the `--ref` document (default `governance/stenio-troubleshooting.md`), runs the backlog audit and prints the id (v4.17.0).
- `stenio verify-host --host H --config <toml> --repo-root <dir>`: `[[parity.files]]` (host, path, repo) compared by sha256 over ssh (PASS/FAIL/DRIFT with both hashes) plus restart policies of all containers (v4.16.0). With `[parity] stenio_container = "<name>"` it also compares the engine version inside that container with the local binary and fails on DRIFT (v4.18.0, GB-030).
- `stenio verify-release --host H --tag T [--project-dir D] [--repo R] [--public-url https://…] [--repo-compose F] [--host-compose F] [--protected-record 'DocType:name:modified'] [--expect-main]`: read-only post-deploy checks over ssh from a fixed command allowlist; one PASS/FAIL/WARN line each, exit 1 on any FAIL. Since v4.18.0 it prints two backup lines: `backup-age` (newest `bench backup`) and `backup-age-scheduled` (newest dump matched by `[frappe] scheduled_backup_glob`, limit `scheduled_backup_max_age_hours`, default 26 h), so a fresh manual backup never masks a stopped timer (GB-032). Since v4.26.0 it also compares two artifacts nobody was comparing: `host-name` reads `host_name` from the site's `site_config.json` (through the backend container) and FAILs naming both values when it is not the declared public URL — `--public-url`, else `[frappe] public_url`, else WARN: the engine does not know the Funnel and never invents a host (GB-127); and `compose-parity` compares the environment **keys** of the repository compose (`--repo-compose`, default `<repo>/compose/frappe/compose.yml` then `<repo>/../miracena-infra/compose/frappe/compose.yml`) with the host's (`--host-compose`, default `<project-dir>/compose.yml`), naming at most 10 keys per side, values never compared (GB-096). Since v4.31.0 the `services` check polls: `--wait-secs N` (default 120, 0 = one single read) re-reads every 5 s until every service is healthy or the deadline passes, the verdict is the last read, and the line ends `(waited Ns)` or `(not converged after Ns)` while still naming the services that did not converge (GB-045). Since v4.32.0 `compose-hash` also compares the SHA-256 of the repository compose with the content read from the host (the same `cat` the parity check uses, no new remote command): PASS prints both 12-hex prefixes, FAIL names both when they differ, WARN when either side cannot be read. The comparison is byte-exact, with no whitespace or line-ending normalisation, because the deploy copies the file as it is and `release.sh` step 9 hashes the same bytes; it closes the gap where `compose-parity` (keys only) passed a changed healthcheck, command or image (GB-229).
- `stenio release-engine --tag vX [--repo .] [--host kuaray] [--container miracena-stenio] [--compose-dir /srv/data/miracena] [--service stenio] [--image-repo ghcr.io/ceduardorodrig/stenio-sentinel] [--wait-secs N] [--build-timeout-secs N] [--install-dir D] [--skip-ci] [--dry-run]`: the release pass from tag to both hosts — local tag at HEAD, tag pushed to origin, the three GitHub runs (`gh run list`, waits), `cargo build --release --locked`, install with a rollback copy `stenio.prev-<old>`, kuaray image retag/pull (exact version, retagged to the moving major the compose file references)/`compose up`, container version parity, `--self-test` and the `vault`/`homelab` scopes; one PASS/FAIL/SKIP line per step, exit 1 on any FAIL (v4.18.0, GB-034; the major retag since v4.18.1).
- `stenio frappe-drift --repo <dir with the Dockerfile> [--runtime-frappe X] (--latest X | --latest-file F | --online)`: compares the `ARG BASE_IMAGE=<img>:vX.Y.Z` pin with the newest stable release of the same major (`FAIL behind: pin -> latest`) and, with `--runtime-frappe`, with the Frappe version the running image reports (`FAIL pin-vs-runtime`); one line, exit 0 PASS / 1 FAIL / 2 no pin or no latest; offline through `--latest`/`--latest-file`, the GitHub releases API through `--online` (v4.30.1, GB-242).
- MCP: `stenio_pre_release`, `stenio_verify_release` and `stenio_verify_host` are tools of the MCP server (stdio and `--mcp-sse`), so an agent on any harness calls them instead of shelling out; arguments are validated and run as an argv vector, and the tool returns the exit code plus the PASS/FAIL lines (v4.18.0, GB-022).

## 🔍 Built-in Rule Catalog & Scopes

| Rule ID | Category | Severity | Description |
|---|:---:|:---:|---|
| `RUST-NO-UNWRAP` | Rust | **ERROR** | Strictly forbids `.unwrap()` and `.expect()` in production code. |
| `ARCH-NO-PYTHON` | Arch | **ERROR** | Enforces 100% native Rust backend sovereignty (ADR-036). |
| `ARCH-DRY-DUPLICATION` | Code | **ERROR/WARN** | Two-layer detection with adaptive severity: substantial logic duplication → ERROR; low-density or short structural matches → WARN. |
| `DOC-VIBE-DISCLAIMER` | Docs | **ERROR** | Enforces the standardized human-AI governance disclaimer across all repositories. |
| `DOC-BACKLOG-DRIFT` | Docs | **ERROR/WARN** | Backlog traceability: the active queue (`mnemocine/backlog.md`) and each document's `pending:` frontmatter must agree bidirectionally. Adaptive severity — a drift on a 🔴 item blocks; any other drift warns. |
| `DOC-BACKLOG-QUEUE-PARITY` | Docs | **ERROR** | The `## 2. Queues` table of `governance/backlog-method.md` and the embedded registry (`backlog-queues.toml`) must agree queue by queue: same queues, same prefixes, the label must be the registry `name` and `Location` must resolve to its `dir`. Silent when the document or the table is absent (hub/product repos). Born from GB-066, where the table said "SUMÆNIMÁ Hub" while the TOML said `hub`. |
| `I18N-PO-INCOMPLETE` | i18n | **ERROR** | Gettext catalogues (`locale/*.po`) must be complete: no empty or fuzzy `msgstr` (plural forms included), every static string passed to `_()`, `__()`, `_lt()` or `{% trans %}` in the sources next to the catalogue must be a `msgid` (with its `msgctxt`), and `{0}`, `%s`, `%(name)s` placeholders must match. Tests and vendored code are skipped. No suppression directive exists for it. |
| `FRAPPE-DOCTYPE-CONTROLLER` | Frappe | **ERROR** | Scope `frappe`: every DocType folder with a `.json` has `<name>.py` defining a class and an `__init__.py` (the rc68 migrate break). |
| `FRAPPE-LINK-TITLE` | Frappe | **ERROR** | A Link field whose target DocType in the app has neither `title_field` + `show_title_field_in_link` nor `search_fields`. Core targets are allowlisted. |
| `FRAPPE-PATCH-REGISTERED` | Frappe | **ERROR** | Every `patches/*.py` is in `patches.txt` and every `patches.txt` line resolves to a module. |
| `FRAPPE-HOOK-TARGETS` | Frappe | **ERROR** | Every dotted app path in `hooks.py` resolves to an existing module and function (static lookup). |
| `FRAPPE-TEST-REGISTERED` | Frappe | **ERROR** (the `*_pure.py` finding is **WARN** while rolled out) | Every `tests/*.py` with `run()` is in the test-list section named by `[frappe] test_list_file` / `test_list_anchor`; every `tests/*_pure.py` is run by the release battery (`names`/`cmds`, same discovery as FRAPPE-TEST-PARITY) or declared `site-only` / `skipped` in that section (GB-150, absorbing GB-139 and GB-220). |
| `FRAPPE-TEST-PARITY` | Frappe | **ERROR** | The pure-test set the `test_list` section declares (`without a site`) and the modules the release battery runs (`names`/`cmds` of `[frappe] battery_file`, else `scripts/release-checks.sh` or the one above the app) must be one set, compared in both directions; unequal arrays, a mislabelled slot and a slot without its file also fail. One side missing → inert WARN that says why. The sibling-repository search resolves the root to its real path, so `--repo .` and `--repo /abs/path` give the same verdict (GB-230). |
| `FRAPPE-SIDEBAR-COVERAGE` | Frappe | **ERROR** | Every non-child DocType is in the sidebar JSON or in the allowlist file (with a reason); every sidebar label has a msgid. |
| `FRAPPE-ROLE-DEFINED` | Frappe | **ERROR** | Every role named in DocType permissions exists in a Role fixture, a patch, or the core list. |
| `FRAPPE-SELECT-CASE` | Frappe | **ERROR** | Select option translations keep the capitalisation pattern of the source. |
| `FRAPPE-WHITELIST-PERMISSION` | Frappe | **WARN** | A `@frappe.whitelist()` function with no permission check. |
| `FRAPPE-DOCTYPE-LABEL-TRANSLATED` | Frappe | **ERROR** | Every label, description, Select option and chart/card label in DocType, sidebar, workspace, number card and dashboard chart JSON has a msgid with a non-empty translation in the app `.po`. |
| `FRAPPE-JSON-MODIFIED-BUMP` | Frappe | **ERROR** | `stenio pre-release --prev`: a changed DocType/Sidebar/Workspace/card/chart/fixture JSON must carry a strictly newer `modified` (Frappe imports only newer files); `[frappe] modified_allowlist` for forced reloads. Also runs in `pre-release --static-only --prev <tag>` / `preflight --prev <tag>` against the working tree (uncommitted edits included), before any tag exists (GB-049). |
| `FRAPPE-FETCH-PARITY` | Frappe | **ERROR** | A child DocType (istable) whose snake_case name matches `doctype_pattern` of a `[[frappe.fetch_parity]]` entry in `steniocheck.toml` (e.g. `*_member`) lacks the entry's `field` (e.g. `role`), or declares it without the expected `fetch_from` (e.g. `member.role`), or without `fetch_if_empty: 1` (relaxed by `fetch_if_empty = false`). No table, no check: the expected values are data, not engine code (GB-241). |
| `JS-DESK-WEB-ONLY-API` | Frappe | **ERROR** | A JS file listed in `app_include_js` of hooks.py (loaded on every Desk page) that calls or reads the website / web-form APIs `frappe.ready`, `frappe.ready_events` or `frappe.web_form`, which the Desk never defines (the rc124 TypeError in nav_permissions.js, fixed in rc125 with the `startup` event). A use is guarded when the same API is tested on its own line or in the 5 lines before; comments, `web_include_js` files and files no hook loads are silent (GB-240). |
| `FRAPPE-REHEARSAL-VERDICT` | Frappe | **ERROR** | The rehearsal script (`[frappe] rehearsal_file`, else `scripts/rehearse.sh`, `compose/frappe/scripts/rehearse.sh` or the one above the app) must derive each module's verdict from a positive signal: one loop over one array, the exit status captured (`\|\| rc=$?`), one `if` requiring status 0 AND a success marker (`=~ (OK\|PASS)$`), failures counted into a non-zero exit, and totals taken from `${#ARRAY[@]}`, never typed. "No Traceback/FAIL" alone, status-only, `\|\| true` and typed totals fail. Script absent → inert WARN (GB-055, rule 12.3). |
| `FRAPPE-RELEASE-ORDER` | Frappe | **ERROR** | The release orchestrator (`[frappe] release_file` / `STENIO_FRAPPE_RELEASE`, else `scripts/release.sh`, `compose/frappe/scripts/release.sh` or the one above the app) must run the offline battery (`release-checks.sh`) before any tag push or `docker build` (GB-165) and before the `__version__` bump or `git tag` (GB-214, a number is spent only after a green battery). Script or battery call not found → inert WARN that says why. |
| `FRAPPE-RELEASE-TAG-BEFORE-REHEARSAL` | Frappe | **WARN** | The same script pushes the tag before it calls the rehearsal: a failed rehearsal then burns a published number (rc125, 2026-11-09). A reminder until `release.sh` publishes the tag after the rehearsal, which needs a Dockerfile change too (GB-196). |
| `FRAPPE-REHEARSAL-PARITY` | Frappe | **ERROR** | The module array of `rehearse.sh` (resolved like FRAPPE-REHEARSAL-VERDICT) is reconciled with the other two test lists. (a) A module declared `site-only`/`skipped` in section 2 of the test-list document but missing from the rehearsal list runs nowhere. (b) A rehearsal module with no `tests/<module>.py` runs nothing. (c) A rehearsal module in neither the release battery nor section 2 runs only in the rehearsal. Script, section or battery not found → inert WARN (GB-137, GB-218, rule 12.4). |
| `FRAPPE-WHITELIST-METHODS` | Frappe | **WARN** | A `@frappe.whitelist()` function that calls `.save/.insert/.delete/.db_set/frappe.delete_doc/frappe.db.set_value` and declares no `methods` (the default accepts GET, POST, PUT and DELETE). The decorator is read over several lines and the `@whitelist` alias is accepted; a writer hidden behind a helper is not seen (GB-052). |
| `FRAPPE-WHITELIST-WRITE-POST` | Frappe | **WARN** | A state-changing whitelisted function whose explicit `methods` list holds a verb other than POST. With the rule above, a writer must declare `methods=["POST"]` exactly (GB-056). |
| `FRAPPE-WHITELIST-NO-CALLER` | Frappe | **WARN** | A whitelisted function whose dotted path no `.js`/`.html`/`.json` (report, card, chart) or other app code names; module and function named apart (a JS helper, `from m import f`) count and whole-line comments are ignored; `[frappe] whitelist_external` exempts an endpoint called from outside (GB-054). |
| `FRAPPE-CURRENCY-THRESHOLD-UNSET` | Frappe | **ERROR** | A threshold comparison over a Currency field resolved against the app's DocType JSONs (`(x or 0) >= LIMIT`, `flt(x) >= LIMIT`, the mirrored form, or an attribute read) with no earlier branch for the empty value: Frappe stores an unfilled Currency as 0.0, so an empty value silently reads zero (GB-123/GB-133). A zero-test (`x <= 0`, `x > 0`) and a name that is not Currency are never accused. |
| `FRAPPE-PERMISSION-SCOPE` | Frappe | **ERROR** | A DocType (not a child table, not a Single) with a field that identifies a person — a Link whose `options` is `Member`/`User`, or a fieldname from the person vocabulary — that grants `read`/`write` to a broad role (`Miracena Member`, `Miracena Freelancer`, `Desk User`, `All`, `Guest`) while `hooks.py` registers neither `permission_query_conditions` nor `has_permission` for it. The allowlist is data (`permissions-public.txt` at the root of the app, one DocType per line with the reason after `#`); a missing file is an empty allowlist. `if_owner` does not silence it: the flag narrows one permission row, not the DocType. |
| `FRAPPE-PUBLISHED-CONTENT-FOLLOWS-THE-IMAGE` | Frappe | **ERROR** | A module in `patches/` listed in `patches.txt` that reads a file shipped in the image (`Path(__file__)`, `read_text`, `open`, `pkgutil.get_data`) and writes a long-text field of a record (`content`, `body`, `html`, `markup`, `page_content`, `long_description`) must also be in `after_migrate` of hooks.py: a patch runs once, so the second edition of the document never reaches the site (GB-142, the stale manual of rc114). A patch that reads no file, a patch that writes no long-text field, and a module in `after_migrate` with no patch line are silent; a commented `after_migrate` registers nothing. |
| `I18N-CASE` | i18n | **ERROR** | `.po` pairs: uppercase first letter follows the msgid; Title Case msgids (2 to 6 words) need a Title Case msgstr except small Portuguese words; sentence case is not forced. |
| `AGENT-ENTRYPOINT-RULES` | Agent | **ERROR** (WARN for optional entries) | Every harness entry file listed in `governance/agent-entrypoints.toml` (Claude Code, OpenCode, Antigravity, Hermes) exists and contains its `must_reference` strings (`agent-global-rules.md`, the rituals reminder); `host_only` entries are skipped with INFO on other hosts. Scopes `vault` and `homelab` (v4.17.0). |
| `STENIO-ITEM-FORMAT` | Backlog | **ERROR** | A backlog row titled `Stenio:` must contain `Evidence:`, `Desired behaviour:`, `Acceptance:`, `Origin:` and `Status:` (v4.17.0). |
| `INFRA-COMPOSE-RESTART-POLICY` | Infra | **ERROR** (WARN in the read-only mirror) | Long-running compose services must be `unless-stopped` or `always`; exempt: profiles `cold`/`tunnel`, one-shots awaited with `service_completed_successfully`, label `homelab.restart-exempt`. |
| `DOC-BACKLOG-RECURRENCE` | Docs | **ERROR/WARN** | Backlog recurrence: a `Recurrence` / `Recurred-by` pair must agree — a recurring item points at an *archived* item, and that archived item points back. Adaptive severity. |
| `DOC-UNVERIFIED-INTERFACE` | Docs | **WARN** | A server/service document names a sysfs path, an I2C address or a charger/PMIC chip with no verification marker in the same section. Silenced by `verified\|measured\|implemented\|confirmed\|checked\|read on` plus an ISO date, in the claim's section or in an ancestor heading. Born from GB-007: notes claimed an `axp20x` PMIC with a `voltage_max` knob on a device whose charger is a Summit SMB327. |
| `DOC-STALE-ACCESS-CLAIM` | Docs | **WARN** | A document asserts that a host has no administrative path or access with nothing saying when that was last true. Matches the claim shape only (`no administrative path/access`, `no admin path`, `sem caminho administrativo`), never the ordinary word "unreachable", which is legitimate alert prose. Same date-marker escape as the rule above. |
| `HOMELAB-BACKLOG-STATE` | Homelab | **WARN** | Backlog split: an id must live in exactly one file, and its state must match (a closed state in the queue, an active state in the archive). |
| `HOMELAB-GPU-UNIFIED` | Homelab | **WARN** | GPU unification: a compose service claiming the GPU (`runtime: nvidia`, `gpus:`, `deploy` device reservations or `NVIDIA_VISIBLE_DEVICES`) must be a registered consumer of the centralized gateway (`hl-infer`, ADR-020). The allowlist is a data file (`mnemocine/network/gpu-consumers.txt`) with an engine fallback. |
| `SEC-SECRETS` | Security | **ERROR** | Blocks plain-text credentials by shape in every file type: GitHub tokens (`gh[opsur]_`, `github_pat_`), AWS key ids, Tailscale keys, Google API keys, Slack tokens, GitLab PATs, JWTs, `Authorization: Bearer` headers, SSH/EC/DSA/RSA private-key headers and keyword-anchored passwords. Scans `.env`, `.env.*`, `*.env`, `*.pem`, `*.key` and the phone-synced `.obsidian/*.json` and `.pandoc/*.json`. SOPS ciphertext never fires. |
| `SEC-PLAINTEXT-SECRET` | Security | **ERROR** | Literal credentials in infrastructure files (`*_PASSWORD`, `*_PASS`, `*_PWD`, `*_SECRET`, `*_SECRET_KEY`, `*_API_KEY`, `*_ACCESS_KEY`, `*PRIVATE_KEY`, `*_AUTHKEY`, `*_AUTH_KEY`, `*_CREDENTIALS`, `*_TOKEN`) plus the token shapes; every hit is reported, not one per file. |
| `SEC-PERM-LEAK` | Security | **ERROR** | Secret-bearing files must not be group-writable or reachable by others: `.env`, `*.env`, `*.pem`, `*.key`, `.docker/config.json` (and `secrets.env`, `keys.txt`, SSH keys, which must be 0600). |
| `SEC-SECRETS-HISTORY` | Security | **ERROR** | Opt-in (`--history`): a credential shape added in any commit of `git log -p --all`, even if deleted later. |
| `SEC-SOPS-UNENCRYPTED` | Security | **ERROR** | Prevents committing unencrypted `.enc.*` files; a dotenv is accepted as encrypted with `sops_mac=`/`sops_version=` markers or `ENC[AES256_GCM` values. |
| `GOV-AGENT-LAWS` | Gov | **ERROR** | Validates agent constitution and governance rules in `AGENTS.md`. |
| `VAULT-TAG-TAXONOMY` | Docs | **WARN** | Restricts tags to canonical taxomony cataloged in `_tags.md`. |

---

## 📜 License

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see [LICENSE](LICENSE).

For proprietary integrations, enterprise compliance, or sovereign deployments without copyleft requirements, contact **SUMÆNIMÁ** ([ceduardorodrig@gmail.com](mailto:ceduardorodrig@gmail.com)).

---

## 📬 Author & Community

- **Creator & Maintainer:** **Carlos Eduardo Rodrigues** ([@ceduardorodrig](https://github.com/ceduardorodrig))
- **Portfolio & Profile:** [ceduardorodrig](https://github.com/ceduardorodrig/ceduardorodrig)
- **Venture:** [Sumænimá](https://sumaenima.chimaera-heptatonic.ts.net)

---

🛡️ Human-in-the-Loop Agentic Engineering

Developed by Carlos Eduardo Rodrigues with AI coding agents.
Every change is verified by the deterministic quality gate StenioSentinel.
