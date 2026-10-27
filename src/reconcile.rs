//! Reconciliation invariants — **observed reality vs declared documents** (HB-052).
//!
//! The homelab drifts because documents and hosts are edited independently: a port
//! matrix that lagged reality, a document claiming a Swarm worker that was never in
//! the Swarm, services running that no document mentions. A rule *per service* does
//! not scale; a **reconciler** does. This module compares the two sides generically
//! and reports the gap:
//!
//!   * `REALITY-UNDECLARED` — an entity observed on a host (a Docker container, a
//!     systemd unit, a listening socket) that **no document declares**.
//!   * `DECLARATION-STALE`  — an entity a document declares that is **no longer
//!     observed** (a `planned`/`retired`/`cold` marker on the row exempts it).
//!   * `PURPOSE-MISSING`   — a declared entity whose row lacks a non-empty
//!     purpose/owner value.
//!   * `POLICY-UNDERIVABLE` — a Tailscale grant that cannot be derived from the
//!     declared catalogue + the documented routes (reported, never edited).
//!
//! ## Data, not code
//!
//! The observation sources live in [`sources.toml`](../../sources.toml) (or a file
//! passed with `--sources`): each block names a host, a read-only command and the
//! generic extractor that reads its output. Adding a host is a data edit.
//!
//! ## Never guess
//!
//! A source that cannot be read (SSH auth required, timeout, non-zero exit) or a
//! table that cannot be parsed is reported as **skipped**, never as a violation —
//! the reconciler has no opinion about what it could not see.
//!
//! The catalogue columns are resolved **from the table header**, so the layout can
//! change without touching the engine. The Tailscale policy is huJSON: it is parsed
//! **structurally** (comments and trailing commas are huJSON syntax, handled before
//! the JSON parse), never with a service-specific regex.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use colored::Colorize;
use serde::Deserialize;

use crate::engine::Violation;
use crate::rule::Severity;

// ── Rule IDs ────────────────────────────────────────────────────────────────

pub const REALITY_UNDECLARED: &str = "REALITY-UNDECLARED";
pub const DECLARATION_STALE: &str = "DECLARATION-STALE";
pub const PURPOSE_MISSING: &str = "PURPOSE-MISSING";
pub const POLICY_UNDERIVABLE: &str = "POLICY-UNDERIVABLE";

const DEFAULT_CATALOG: &str = "mnemocine/services-catalog.md";
const DEFAULT_POLICY: &str = "/mnt/NVME_PCI/homelab/mnemocine-acl/policy.hujson";
const VAULT_ROOT: &str = "/mnt/NVME_PCI/agentic-ai";

// ── Sources manifest (sources.toml) ─────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SourcesManifest {
    #[serde(default)]
    pub reconcile: ReconcileConfig,
    #[serde(default, rename = "source")]
    pub sources: Vec<SourceSpec>,
    #[serde(default)]
    pub aliases: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ReconcileConfig {
    pub catalog: Option<String>,
    pub policy: Option<String>,
    #[serde(default)]
    pub route_docs: Vec<String>,
    #[serde(default)]
    pub exempt_markers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourceSpec {
    pub host: String,
    pub parser: String,
    pub command: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

fn yes() -> bool {
    true
}

impl SourcesManifest {
    fn load(path: &Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        toml::from_str(&content).ok()
    }
}

// ── Entities ────────────────────────────────────────────────────────────────

/// One entity as seen on a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    pub name: String,
    /// Operator-managed (a systemd unit under `/etc` or `~/.config`). Base-OS
    /// units are still visible for staleness, but hidden from REALITY-UNDECLARED.
    pub operator: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceOutcome {
    Observed(Vec<Entity>),
    /// The source could not be read — a note, never a violation.
    Skipped(String),
}

#[derive(Debug, Clone)]
pub struct Observation {
    pub host: String,
    pub parser: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub outcome: SourceOutcome,
}

impl Observation {
    pub fn observed(host: &str, parser: &str, names: &[&str]) -> Self {
        Observation {
            host: host.to_string(),
            parser: parser.to_string(),
            include: Vec::new(),
            exclude: Vec::new(),
            outcome: SourceOutcome::Observed(
                names
                    .iter()
                    .map(|n| Entity {
                        name: (*n).to_string(),
                        operator: true,
                    })
                    .collect(),
            ),
        }
    }

    /// A source that could not be read (used by the tests and callers).
    #[allow(dead_code)]
    pub fn skipped(host: &str, parser: &str, reason: &str) -> Self {
        Observation {
            host: host.to_string(),
            parser: parser.to_string(),
            include: Vec::new(),
            exclude: Vec::new(),
            outcome: SourceOutcome::Skipped(reason.to_string()),
        }
    }
}

// ── Declared entities (service catalogue) ───────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DeclKind {
    Container,
    Native,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DeclaredEntity {
    pub host: String,
    pub name: String,
    pub kind: DeclKind,
    pub purpose_present: bool,
    pub owner_present: bool,
    pub exempt: bool,
    pub line: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Catalog {
    pub entities: Vec<DeclaredEntity>,
    /// `(host, tailnet-ip)` read from the section headings.
    pub hosts: Vec<(String, String)>,
    pub skipped_tables: Vec<String>,
    pub skipped_rows: usize,
}

impl Catalog {
    /// Every declared tailnet IP (used as the derivability ground truth).
    pub fn host_ips(&self) -> BTreeSet<String> {
        self.hosts.iter().map(|(_, ip)| ip.clone()).collect()
    }
}

// ── Tailscale policy (huJSON) ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Grant {
    pub raw: String,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    pub ip: Vec<String>,
    pub has_app: bool,
    pub line: usize,
}

/// Documented routes: subnet CIDRs and peer/exit-node IPs from the network notes.
#[derive(Debug, Clone, Default)]
pub struct RouteIndex {
    pub ips: BTreeSet<String>,
    pub cidrs: BTreeSet<String>,
}

// ── Markdown table extraction (header-driven) ───────────────────────────────

/// Splits a Markdown table line into trimmed cells (`| a | b |` → `["a","b"]`).
fn cells_of(line: &str) -> Vec<String> {
    let body = line.trim().trim_start_matches('|').trim_end_matches('|');
    body.split('|').map(|c| c.trim().to_string()).collect()
}

/// True for a `|---|---|:--:|` separator row.
fn is_rule_row(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
}

/// Normalises a header cell for role lookup (`**Why it exists**` → `why it exists`).
fn header_key(cell: &str) -> String {
    cell.trim()
        .trim_matches(|c: char| c == '*' || c == '`' || c == '_' || c.is_whitespace())
        .to_lowercase()
}

/// Position of the first header cell matching any of `aliases`.
fn find_column(header: &[String], aliases: &[&str]) -> Option<usize> {
    header.iter().position(|cell| {
        let key = header_key(cell);
        aliases.iter().any(|a| key == *a)
    })
}

#[derive(Debug, Clone, Copy)]
struct ServiceColumns {
    service: usize,
    purpose: Option<usize>,
    owner: Option<usize>,
    how: Option<usize>,
}

/// Resolves the catalogue layout from the header row. `None` when the table has
/// no service column (the legend, §(a) and §(b) tables are therefore ignored).
fn resolve_service_columns(header: &[String]) -> Option<ServiceColumns> {
    Some(ServiceColumns {
        service: find_column(header, &["service", "name", "unit", "container"])?,
        purpose: find_column(
            header,
            &[
                "why it exists",
                "purpose",
                "what it does",
                "what it does (1 line)",
                "function",
                "role",
                "why",
            ],
        ),
        owner: find_column(
            header,
            &["owner", "who owns it", "maintainer", "accountable"],
        ),
        how: find_column(header, &["how", "kind", "type", "mode"]),
    })
}

fn cell_has_value(cell: Option<&String>) -> bool {
    cell.is_some_and(|c| {
        let t = c.trim();
        !t.is_empty() && t != "—" && t != "-"
    })
}

fn classify_kind(how: &str) -> DeclKind {
    let h = how.to_lowercase();
    if h.contains("swarm") || h.contains("container") {
        DeclKind::Container
    } else if h.contains("native") || h.contains("binary") || h.contains("systemd") {
        DeclKind::Native
    } else {
        DeclKind::Unknown
    }
}

/// Parses the service catalogue: every table whose header carries a `service`
/// column, under a `## <host> — <ip>` section, becomes declared entities.
pub fn parse_catalog(content: &str) -> Catalog {
    let lines: Vec<&str> = content.lines().collect();
    let mut catalog = Catalog::default();
    let mut host = String::new();
    let mut i = 0usize;

    while i < lines.len() {
        let trimmed = lines[i].trim();

        if let Some(rest) = trimmed.strip_prefix("## ") {
            match extract_ipv4(rest) {
                Some(ip) => {
                    let name = heading_host(rest);
                    host = name.clone();
                    catalog.hosts.push((name, ip));
                }
                // Legend / §(a) / §(b) sections are not per-host tables.
                None => host.clear(),
            }
            i += 1;
            continue;
        }

        if !host.is_empty() && trimmed.starts_with('|') {
            // A real header is followed by a `|---|` rule row; without it the
            // line is data (e.g. a legend row that happens to contain "service").
            let is_header = i + 1 < lines.len() && is_rule_row(&cells_of(lines[i + 1].trim()));
            let header = cells_of(trimmed);
            if is_header && let Some(cols) = resolve_service_columns(&header) {
                let mut j = i + 2;
                let mut missing = Vec::new();
                if cols.purpose.is_none() {
                    missing.push("purpose");
                }
                if cols.owner.is_none() {
                    missing.push("owner");
                }
                if !missing.is_empty() {
                    catalog.skipped_tables.push(format!(
                        "service table for host '{}' has no {} column (PURPOSE-MISSING not evaluated)",
                        host,
                        missing.join(" / ")
                    ));
                }

                while j < lines.len() {
                    let row = lines[j].trim();
                    if !row.starts_with('|') {
                        break;
                    }
                    let cells = cells_of(row);
                    if is_rule_row(&cells) {
                        j += 1;
                        continue;
                    }
                    let service = cells.get(cols.service).map(|s| s.as_str()).unwrap_or("");
                    if service.trim().is_empty() {
                        catalog.skipped_rows += 1;
                        j += 1;
                        continue;
                    }
                    let needed = [Some(cols.service), cols.purpose, cols.owner]
                        .into_iter()
                        .flatten()
                        .max()
                        .unwrap_or(0);
                    if cells.len() <= needed {
                        // A structurally short row is skipped, never a violation.
                        catalog.skipped_rows += 1;
                        j += 1;
                        continue;
                    }
                    catalog.entities.push(DeclaredEntity {
                        host: host.clone(),
                        name: service.to_string(),
                        kind: cols
                            .how
                            .and_then(|idx| cells.get(idx))
                            .map(|c| classify_kind(c))
                            .unwrap_or(DeclKind::Unknown),
                        purpose_present: cols
                            .purpose
                            .is_none_or(|idx| cell_has_value(cells.get(idx))),
                        owner_present: cols.owner.is_none_or(|idx| cell_has_value(cells.get(idx))),
                        exempt: false,
                        line: j + 1,
                    });
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }

    catalog
}

/// Marks declared rows carrying an exempt marker as intentionally absent.
pub fn apply_exempt_markers(catalog: &mut Catalog, content: &str, markers: &[String]) {
    let lines: Vec<&str> = content.lines().collect();
    for ent in &mut catalog.entities {
        let row = lines
            .get(ent.line.saturating_sub(1))
            .map(|l| l.to_lowercase())
            .unwrap_or_default();
        ent.exempt = markers
            .iter()
            .any(|m| !m.is_empty() && row.contains(&m.to_lowercase()));
    }
}

// ── Name normalisation ──────────────────────────────────────────────────────

/// Canonical key: lowercase, `._/ ` → `-`, punctuation dropped.
fn canonical(name: &str) -> String {
    let mut out = String::new();
    let mut prev_sep = false;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if (ch == '-' || ch == '.' || ch == '/' || ch == ' ' || ch == '(' || ch == ')')
            && !prev_sep
            && !out.is_empty()
        {
            out.push('-');
            prev_sep = true;
        }
    }
    out.trim_end_matches('-').to_string()
}

fn apply_alias(key: &str, aliases: &HashMap<String, String>) -> String {
    aliases.get(key).cloned().unwrap_or_else(|| key.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeclToken {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Unresolved,
}

/// Expands the first `{a,b,c}` brace group into comma-separated alternatives.
fn expand_braces(s: &str) -> String {
    let Some(open) = s.find('{') else {
        return s.to_string();
    };
    let Some(close_rel) = s[open..].find('}') else {
        return s.to_string();
    };
    let close = open + close_rel;
    let prefix = &s[..open];
    let inner = &s[open + 1..close];
    let suffix = &s[close + 1..];
    inner
        .split(',')
        .map(|alt| format!("{}{}{}", prefix, alt.trim(), suffix))
        .collect::<Vec<_>>()
        .join(",")
}

/// Splits a declared service cell into name tokens: braces expanded, then split
/// on `/`, `,` and `+`. `hl-*` → prefix, `-mariadb` → suffix (a family member),
/// `—`/empty → unresolved (skipped, never flagged).
fn split_declared_names(cell: &str) -> Vec<DeclToken> {
    let expanded = expand_braces(cell);
    let mut tokens = Vec::new();
    for part in expanded.split(['/', ',', '+']) {
        let raw = part.trim();
        if raw.is_empty() {
            continue;
        }
        if raw.contains('*') {
            let prefix = raw.split('*').next().unwrap_or("").trim().to_lowercase();
            if prefix.is_empty() {
                tokens.push(DeclToken::Unresolved);
            } else {
                tokens.push(DeclToken::Prefix(prefix));
            }
            continue;
        }
        if let Some(rest) = raw.strip_prefix('-') {
            let key = canonical(rest);
            if key.is_empty() {
                tokens.push(DeclToken::Unresolved);
            } else {
                tokens.push(DeclToken::Suffix(format!("-{key}")));
            }
            continue;
        }
        let key = canonical(raw);
        if key.is_empty() {
            tokens.push(DeclToken::Unresolved);
        } else {
            tokens.push(DeclToken::Exact(key));
        }
    }
    tokens
}

fn is_declared(
    name: &str,
    keys: &BTreeSet<String>,
    prefixes: &[String],
    suffixes: &[String],
) -> bool {
    if keys.contains(name) {
        return true;
    }
    if prefixes.iter().any(|p| name.starts_with(p.as_str())) {
        return true;
    }
    suffixes.iter().any(|s| name.ends_with(s.as_str()))
}

/// Minimal glob matcher (only `*` is special).
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut remaining = text;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            match remaining.strip_prefix(part) {
                Some(rest) => remaining = rest,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return remaining.ends_with(part);
        } else {
            match remaining.find(part) {
                Some(idx) => remaining = &remaining[idx + part.len()..],
                None => return false,
            }
        }
    }
    true
}

fn passes_filters(name: &str, include: &[String], exclude: &[String]) -> bool {
    if !include.is_empty() && !include.iter().any(|p| glob_match(p, name)) {
        return false;
    }
    !exclude.iter().any(|p| glob_match(p, name))
}

// ── Generic extractors ──────────────────────────────────────────────────────

/// Swarm task containers are named `service.<slot>.<hash>`; keep the service.
fn strip_swarm_task(name: &str) -> String {
    if let Some(dot) = name.find('.') {
        let rest = &name[dot + 1..];
        if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return name[..dot].to_string();
        }
    }
    name.to_string()
}

pub fn parse_docker_names(stdout: &str) -> Vec<Entity> {
    stdout
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| Entity {
            name: strip_swarm_task(l),
            operator: true,
        })
        .collect()
}

pub fn parse_systemd_units(stdout: &str) -> Vec<Entity> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, '\t');
        let name = parts.next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        let path = parts.next().unwrap_or("").trim();
        let unit = name.strip_suffix(".service").unwrap_or(name).to_string();
        let operator = path.starts_with("/etc/systemd/") || path.contains("/.config/systemd/");
        out.push(Entity {
            name: unit,
            operator,
        });
    }
    out
}

pub fn parse_ss_processes(stdout: &str) -> Vec<Entity> {
    let mut seen = BTreeSet::new();
    for line in stdout.lines() {
        if let Some(idx) = line.find("users:((\"") {
            let rest = &line[idx + 9..];
            if let Some(end) = rest.find('"') {
                let name = &rest[..end];
                if !name.is_empty() {
                    seen.insert(name.to_string());
                }
            }
        }
    }
    seen.into_iter()
        .map(|name| Entity {
            name,
            operator: true,
        })
        .collect()
}

pub fn parse_plain_lines(stdout: &str) -> Vec<Entity> {
    stdout
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| Entity {
            name: l.to_string(),
            operator: true,
        })
        .collect()
}

fn parse_entities(parser: &str, stdout: &str) -> Vec<Entity> {
    match parser {
        "docker_names" | "docker_ps" => parse_docker_names(stdout),
        "systemd_units" | "systemd_user_units" => parse_systemd_units(stdout),
        "ss_processes" => parse_ss_processes(stdout),
        _ => parse_plain_lines(stdout),
    }
}

fn parser_kind(parser: &str) -> DeclKind {
    match parser {
        "docker_names" | "docker_ps" => DeclKind::Container,
        "systemd_units" | "systemd_user_units" => DeclKind::Native,
        _ => DeclKind::Unknown,
    }
}

// ── Invariants 1-3: reality vs declaration ──────────────────────────────────

/// Compares the declared catalogue with the observations and returns
/// `(violations, skipped notes)`. Pure — the tests call it directly.
pub fn reconcile_all(
    catalog: &Catalog,
    catalog_display: &str,
    observations: &[Observation],
    aliases: &HashMap<String, String>,
) -> (Vec<Violation>, Vec<String>) {
    let mut violations = Vec::new();
    let mut notes = Vec::new();

    // Declared keys (alias-normalised) + family matchers.
    let mut declared_keys: BTreeSet<String> = BTreeSet::new();
    let mut declared_prefixes: Vec<String> = Vec::new();
    let mut declared_suffixes: Vec<String> = Vec::new();
    for ent in &catalog.entities {
        for token in split_declared_names(&ent.name) {
            match token {
                DeclToken::Exact(k) => {
                    declared_keys.insert(apply_alias(&k, aliases));
                }
                DeclToken::Prefix(p) => declared_prefixes.push(p),
                DeclToken::Suffix(s) => declared_suffixes.push(s),
                DeclToken::Unresolved => {}
            }
        }
    }

    // Observed names and kinds per host (all successful sources).
    let mut observed_names: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut observed_kinds: HashMap<String, BTreeSet<DeclKind>> = HashMap::new();
    for obs in observations {
        if let SourceOutcome::Observed(entities) = &obs.outcome {
            let names = observed_names.entry(obs.host.clone()).or_default();
            for e in entities {
                let key = canonical(&e.name);
                if !key.is_empty() {
                    names.insert(key);
                }
            }
            observed_kinds
                .entry(obs.host.clone())
                .or_default()
                .insert(parser_kind(&obs.parser));
        } else if let SourceOutcome::Skipped(reason) = &obs.outcome {
            notes.push(format!(
                "skipped source [{}/{}]: {}",
                obs.host, obs.parser, reason
            ));
        }
    }

    // ── REALITY-UNDECLARED ──────────────────────────────────────────────────
    for obs in observations {
        let SourceOutcome::Observed(entities) = &obs.outcome else {
            continue;
        };
        for e in entities {
            if !e.operator {
                continue;
            }
            let key = canonical(&e.name);
            if key.is_empty() || !passes_filters(&e.name, &obs.include, &obs.exclude) {
                continue;
            }
            if is_declared(&key, &declared_keys, &declared_prefixes, &declared_suffixes) {
                continue;
            }
            violations.push(Violation {
                rule_id: REALITY_UNDECLARED.to_string(),
                rule_name: "Observed Entity Not Declared".to_string(),
                severity: Severity::Warning,
                file_path: catalog_display.to_string(),
                line_number: 1,
                snippet: e.name.clone(),
                message: format!(
                    "Entity '{}' is running on '{}' but no document declares it.",
                    e.name, obs.host
                ),
                suggestion: Some(format!(
                    "Declare '{}' in {} (add the row with purpose and owner), or stop it.",
                    e.name, catalog_display
                )),
            });
        }
    }

    // ── DECLARATION-STALE ───────────────────────────────────────────────────
    for ent in &catalog.entities {
        if ent.exempt {
            continue;
        }
        let Some(kinds) = observed_kinds.get(&ent.host) else {
            continue;
        };
        if ent.kind == DeclKind::Unknown || !kinds.contains(&ent.kind) {
            continue;
        }
        let Some(names) = observed_names.get(&ent.host) else {
            continue;
        };
        for token in split_declared_names(&ent.name) {
            if let DeclToken::Exact(k) = token {
                let key = apply_alias(&k, aliases);
                if !names.contains(&key) {
                    violations.push(Violation {
                        rule_id: DECLARATION_STALE.to_string(),
                        rule_name: "Declared Entity Not Observed".to_string(),
                        severity: Severity::Warning,
                        file_path: catalog_display.to_string(),
                        line_number: ent.line,
                        snippet: ent.name.clone(),
                        message: format!(
                            "'{}' declares '{}' on '{}', but it was not observed (no running {}).",
                            catalog_display,
                            key,
                            ent.host,
                            if ent.kind == DeclKind::Container {
                                "container"
                            } else {
                                "unit"
                            }
                        ),
                        suggestion: Some(
                            "Remove the row, correct its name, or mark it 'planned'/'retired' if the absence is intentional."
                                .to_string(),
                        ),
                    });
                }
            }
        }
    }

    // ── PURPOSE-MISSING ─────────────────────────────────────────────────────
    for ent in &catalog.entities {
        if ent.purpose_present && ent.owner_present {
            continue;
        }
        let mut missing = Vec::new();
        if !ent.purpose_present {
            missing.push("purpose");
        }
        if !ent.owner_present {
            missing.push("owner");
        }
        violations.push(Violation {
            rule_id: PURPOSE_MISSING.to_string(),
            rule_name: "Declared Row Missing Purpose or Owner".to_string(),
            severity: Severity::Warning,
            file_path: catalog_display.to_string(),
            line_number: ent.line,
            snippet: ent.name.clone(),
            message: format!(
                "'{}' row on '{}' has no {} value.",
                ent.name,
                ent.host,
                missing.join(" or ")
            ),
            suggestion: Some(
                "Fill the purpose/owner column — a row without an accountable purpose is not a declaration."
                    .to_string(),
            ),
        });
    }

    for table in &catalog.skipped_tables {
        notes.push(format!("skipped table: {table}"));
    }
    if catalog.skipped_rows > 0 {
        notes.push(format!(
            "skipped {} malformed catalogue row(s) (short/empty service cell) — reported as skipped, not as violations",
            catalog.skipped_rows
        ));
    }
    for (host, _) in &catalog.hosts {
        if !observed_names.contains_key(host) && catalog.entities.iter().any(|e| &e.host == host) {
            notes.push(format!(
                "host '{host}' has declarations but no readable observation — staleness not evaluated"
            ));
        }
    }

    (violations, notes)
}

// ── Invariant 4: Tailscale policy derivability ──────────────────────────────

fn is_ipv4(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()))
}

fn is_cidr(token: &str) -> bool {
    let Some((addr, prefix)) = token.split_once('/') else {
        return false;
    };
    is_ipv4(addr)
        && !prefix.is_empty()
        && prefix.len() <= 2
        && prefix.chars().all(|c| c.is_ascii_digit())
}

/// Splits a text into address-shaped tokens (`[0-9./]+`), ignoring everything else.
fn addr_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() || ch == '.' || ch == '/' {
            cur.push(ch);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn extract_ipv4(s: &str) -> Option<String> {
    addr_tokens(s).into_iter().find(|t| is_ipv4(t))
}

/// `## psicopompo — `100.82.51.112`` → `psicopompo`.
fn heading_host(rest: &str) -> String {
    let cleaned: String = rest
        .chars()
        .map(|c| if c == '`' || c == '*' { ' ' } else { c })
        .collect();
    let before = match extract_ipv4(&cleaned) {
        Some(ip) => {
            let idx = cleaned.find(&ip).unwrap_or(cleaned.len());
            &cleaned[..idx]
        }
        None => &cleaned,
    };
    before
        .trim()
        .trim_end_matches(|c: char| c == '—' || c == '-' || c == ':' || c.is_whitespace())
        .trim()
        .to_lowercase()
}

/// Indexes the documented routes (CIDRs + IPs) from the network notes.
pub fn index_routes(docs: &[String]) -> RouteIndex {
    let mut index = RouteIndex::default();
    for doc in docs {
        for token in addr_tokens(doc) {
            if is_cidr(&token) {
                index.cidrs.insert(token);
            } else if is_ipv4(&token) {
                index.ips.insert(token);
            }
        }
    }
    index
}

/// Removes huJSON `//` and `/* */` comments, respecting string literals.
fn strip_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut in_str = false;
    let mut escape = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_str {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
                i += 1;
            }
            '/' if i + 1 < bytes.len() && bytes[i + 1] as char == '/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < bytes.len() && bytes[i + 1] as char == '*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Drops trailing commas (`,}` / `,]`) — huJSON syntax that strict JSON rejects.
fn strip_trailing_commas(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut in_str = false;
    let mut escape = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_str {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == ',' {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b'}' || bytes[j] == b']') {
                i += 1; // drop the trailing comma
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Normalises huJSON into strict JSON: strips comments **first**, then trailing
/// commas. huJSON is a superset of JSON, so this is a structural pre-pass — not a
/// regex over the policy. (Order matters: a comment sitting between a comma and
/// its closing bracket must be gone before the trailing-comma scan.)
fn hujson_to_json(input: &str) -> String {
    strip_trailing_commas(&strip_comments(input))
}

/// Parses the `grants` array structurally. `Err` when the file is not readable as
/// huJSON (the caller reports it as skipped, never as a violation).
pub fn parse_policy_grants(content: &str) -> Result<Vec<Grant>, String> {
    let json = hujson_to_json(content);
    let value: serde_json::Value = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    let Some(arr) = value.get("grants").and_then(|g| g.as_array()) else {
        return Ok(Vec::new());
    };
    let mut grants = Vec::new();
    for item in arr {
        let strings = |key: &str| {
            item.get(key)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        grants.push(Grant {
            raw: serde_json::to_string(item).unwrap_or_default(),
            src: strings("src"),
            dst: strings("dst"),
            ip: strings("ip"),
            has_app: item.get("app").is_some(),
            line: 1,
        });
    }
    Ok(grants)
}

/// Why a grant cannot be derived from the catalogue + documented routes (`None`
/// means it is derivable).
fn grant_underivable_reason(
    grant: &Grant,
    declared_ips: &BTreeSet<String>,
    routes: &RouteIndex,
) -> Option<String> {
    let known = |ip: &str| declared_ips.contains(ip) || routes.ips.contains(ip);

    if grant.has_app {
        for dst in &grant.dst {
            if dst == "*" {
                return Some("capability grant targets every destination (dst: *)".to_string());
            }
            if is_ipv4(dst) && !known(dst) {
                return Some(format!("capability grant targets undeclared host {dst}"));
            }
        }
        return None;
    }

    // A routing grant (exit node / subnet route) legitimately carries `ip: *`:
    // it grants L3 reachability to a route, not access to service ports, so it
    // cannot be enumerated from a service catalogue. It is derivable only when
    // the route itself is documented (`autogroup:internet`, or a documented CIDR).
    let routing = grant
        .dst
        .iter()
        .any(|d| d == "autogroup:internet" || (is_cidr(d) && routes.cidrs.contains(d)));

    for dst in &grant.dst {
        if dst == "*" {
            return Some(format!(
                "grants src {:?} → every destination (dst: *) — not derivable from any catalogue",
                grant.src
            ));
        }
        if is_ipv4(dst) {
            if !known(dst) {
                return Some(format!("targets undeclared host {dst}"));
            }
        } else if is_cidr(dst) && !routes.cidrs.contains(dst) {
            return Some(format!("targets undocumented route {dst}"));
        }
    }

    if !routing {
        for ip in &grant.ip {
            if ip == "*" {
                return Some(
                    "grants every port/protocol (ip: *) — not derivable from any catalogue"
                        .to_string(),
                );
            }
        }
    }
    None
}

/// Emits `POLICY-UNDERIVABLE` for every grant that is not derivable.
pub fn check_policy(
    grants: &[Grant],
    declared_ips: &BTreeSet<String>,
    routes: &RouteIndex,
    policy_display: &str,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    for grant in grants {
        if let Some(reason) = grant_underivable_reason(grant, declared_ips, routes) {
            violations.push(Violation {
                rule_id: POLICY_UNDERIVABLE.to_string(),
                rule_name: "Tailscale Grant Not Derivable".to_string(),
                severity: Severity::Warning,
                file_path: policy_display.to_string(),
                line_number: grant.line,
                snippet: grant.raw.clone(),
                message: format!(
                    "Tailscale grant cannot be derived from the declared catalogue + documented routes: {}.",
                    reason
                ),
                suggestion: Some(
                    "Derive the grant from the catalogue (least privilege) and the documented routes, or document the destination/route. The policy itself is never edited by the engine."
                        .to_string(),
                ),
            });
        }
    }
    violations
}

// ── Runner (--reconcile) ────────────────────────────────────────────────────

fn resolve_doc(repo_root: &Path, rel: &str) -> PathBuf {
    let primary = repo_root.join(rel);
    if primary.is_file() {
        return primary;
    }
    PathBuf::from(VAULT_ROOT).join(rel)
}

fn resolve_manifest(repo_root: &Path, override_path: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = override_path {
        return if p.is_file() {
            Some(p.to_path_buf())
        } else {
            None
        };
    }
    let candidates = [
        repo_root.join("sources.toml"),
        repo_root.join("governance/stenio/sources.toml"),
        PathBuf::from("/mnt/NVME_PCI/agentic-ai/governance/stenio/sources.toml"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

fn run_source(spec: &SourceSpec) -> SourceOutcome {
    if !spec.enabled {
        return SourceOutcome::Skipped("disabled in manifest".to_string());
    }
    let timeout = spec.timeout_secs.unwrap_or(8);
    let stdout = match spec.transport.as_str() {
        "ssh" => match crate::remote::run_ssh(&spec.host, &spec.command, timeout) {
            crate::remote::RemoteOutcome::Success(s) => s,
            crate::remote::RemoteOutcome::AuthRequired { .. } => {
                return SourceOutcome::Skipped("Tailscale SSH authentication required".to_string());
            }
            crate::remote::RemoteOutcome::Timeout { .. } => {
                return SourceOutcome::Skipped("SSH timeout".to_string());
            }
            crate::remote::RemoteOutcome::Unreachable { reason, .. } => {
                return SourceOutcome::Skipped(format!("unreachable: {reason}"));
            }
            crate::remote::RemoteOutcome::Failed { error, .. } => {
                return SourceOutcome::Skipped(format!("command failed: {error}"));
            }
        },
        _ => match Command::new("sh").arg("-c").arg(&spec.command).output() {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            Ok(o) => {
                return SourceOutcome::Skipped(format!(
                    "command exited {}: {}",
                    o.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&o.stderr).trim()
                ));
            }
            Err(e) => return SourceOutcome::Skipped(format!("cannot execute: {e}")),
        },
    };
    SourceOutcome::Observed(parse_entities(&spec.parser, &stdout))
}

/// `stenio --reconcile` — observes the hosts (read-only) and reports the drift.
pub fn run_reconcile(repo_root: &Path, sources_override: Option<&Path>, json: bool) -> Result<()> {
    let manifest_path = resolve_manifest(repo_root, sources_override);
    let manifest = manifest_path
        .as_ref()
        .and_then(|p| SourcesManifest::load(p))
        .unwrap_or_default();
    let manifest_display = manifest_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(none — no sources configured)".to_string());

    let catalog_rel = manifest
        .reconcile
        .catalog
        .clone()
        .unwrap_or_else(|| DEFAULT_CATALOG.to_string());
    let catalog_path = resolve_doc(repo_root, &catalog_rel);
    let catalog_display = catalog_path
        .strip_prefix(repo_root)
        .unwrap_or(&catalog_path)
        .to_string_lossy()
        .to_string();

    let policy_rel = manifest
        .reconcile
        .policy
        .clone()
        .unwrap_or_else(|| DEFAULT_POLICY.to_string());
    let policy_path = if Path::new(&policy_rel).is_absolute() {
        PathBuf::from(&policy_rel)
    } else {
        resolve_doc(repo_root, &policy_rel)
    };
    let policy_display = policy_path
        .strip_prefix(repo_root)
        .unwrap_or(&policy_path)
        .to_string_lossy()
        .to_string();

    let mut notes: Vec<String> = Vec::new();
    let mut violations: Vec<Violation> = Vec::new();

    // 1. Declared catalogue.
    let catalog_content = fs::read_to_string(&catalog_path).ok();
    let mut catalog = match catalog_content.as_deref() {
        Some(content) => {
            let mut c = parse_catalog(content);
            apply_exempt_markers(&mut c, content, &manifest.reconcile.exempt_markers);
            c
        }
        None => {
            notes.push(format!(
                "catalogue '{catalog_display}' is unreadable — reconciliation skipped"
            ));
            Catalog::default()
        }
    };

    // 2. Observations (read-only).
    let observations: Vec<Observation> = manifest
        .sources
        .iter()
        .map(|spec| {
            let outcome = run_source(spec);
            Observation {
                host: spec.host.clone(),
                parser: spec.parser.clone(),
                include: spec.include.clone(),
                exclude: spec.exclude.clone(),
                outcome,
            }
        })
        .collect();

    // 3. Documented routes.
    let route_contents: Vec<String> = manifest
        .reconcile
        .route_docs
        .iter()
        .filter_map(|rel| fs::read_to_string(resolve_doc(repo_root, rel)).ok())
        .collect();
    let routes = index_routes(&route_contents);

    // 4. Policy (read-only).
    let mut grants: Vec<Grant> = Vec::new();
    match fs::read_to_string(&policy_path) {
        Ok(content) => match parse_policy_grants(&content) {
            Ok(g) => grants = g,
            Err(e) => notes.push(format!(
                "policy '{policy_display}' is not parsable huJSON ({e}) — POLICY-UNDERIVABLE skipped"
            )),
        },
        Err(_) => notes.push(format!(
            "policy '{policy_display}' is unreadable — POLICY-UNDERIVABLE skipped"
        )),
    }

    // 5. Evaluate the four invariants.
    let (mut reconcile_v, mut reconcile_notes) =
        reconcile_all(&catalog, &catalog_display, &observations, &manifest.aliases);
    violations.append(&mut reconcile_v);
    notes.append(&mut reconcile_notes);

    let declared_ips = catalog.host_ips();
    violations.extend(check_policy(
        &grants,
        &declared_ips,
        &routes,
        &policy_display,
    ));

    // The catalogue owns its own declared hosts; keep the field used.
    catalog.hosts.shrink_to_fit();

    if json {
        println!("{}", serde_json::to_string_pretty(&violations)?);
        return Ok(());
    }

    crate::baseline::print_banner(
        "StenioSentinel — Reconciliation: observed reality vs declared documents (--reconcile)",
    );
    println!("   Manifest:  {}", manifest_display.cyan());
    println!("   Catalogue: {}", catalog_display.cyan());
    println!("   Policy:    {}", policy_display.cyan());
    println!();

    for rule in [
        REALITY_UNDECLARED,
        DECLARATION_STALE,
        PURPOSE_MISSING,
        POLICY_UNDERIVABLE,
    ] {
        let group: Vec<&Violation> = violations.iter().filter(|v| v.rule_id == rule).collect();
        println!(
            "{}",
            format!(
                "── {} ({}) ──────────────────────────────────────",
                rule,
                group.len()
            )
            .dimmed()
        );
        if group.is_empty() {
            println!("   ✅ no finding");
        }
        for v in group {
            println!(
                "   {} {}:{}  {}",
                "•".yellow(),
                v.file_path.dimmed(),
                v.line_number,
                v.message
            );
        }
        println!();
    }

    if !notes.is_empty() {
        println!(
            "{}",
            "── Skipped (reported, never a violation) ─────────────────────".dimmed()
        );
        for n in &notes {
            println!("   {} {}", "⚠️".yellow(), n);
        }
        println!();
    }

    println!(
        "Summary: {} finding(s) across {} invariant(s); {} skipped note(s).",
        violations.len().to_string().bold(),
        violations
            .iter()
            .map(|v| v.rule_id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            .to_string()
            .bold(),
        notes.len()
    );
    println!();
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn declared(host: &str, name: &str, kind: DeclKind) -> DeclaredEntity {
        DeclaredEntity {
            host: host.to_string(),
            name: name.to_string(),
            kind,
            purpose_present: true,
            owner_present: true,
            exempt: false,
            line: 1,
        }
    }

    fn catalog_of(entities: Vec<DeclaredEntity>) -> Catalog {
        Catalog {
            entities,
            hosts: vec![("h".to_string(), "100.0.0.1".to_string())],
            skipped_tables: Vec::new(),
            skipped_rows: 0,
        }
    }

    fn no_alias() -> HashMap<String, String> {
        HashMap::new()
    }

    // ── Extractors ──────────────────────────────────────────────────────────

    #[test]
    fn catalog_columns_resolve_by_header_in_any_order() {
        // owner before purpose, service last: the layout is read from the header.
        let doc = "## host — 100.0.0.1\n\
                   | owner | why it exists | how | service |\n\
                   |---|---|---|---|\n\
                   | edu | transcription | container | steniorec |";
        let catalog = parse_catalog(doc);
        assert_eq!(catalog.entities.len(), 1);
        let e = &catalog.entities[0];
        assert_eq!(e.name, "steniorec");
        assert_eq!(e.kind, DeclKind::Container);
        assert!(e.purpose_present && e.owner_present);
    }

    #[test]
    fn malformed_row_is_skipped_not_flagged() {
        let doc = "## host — 100.0.0.1\n\
                   | service | why it exists | how | owner |\n\
                   |---|---|---|---|\n\
                   | steniorec | transcription | container | edu |\n\
                   | broken | short |";
        let catalog = parse_catalog(doc);
        assert_eq!(catalog.entities.len(), 1);
        assert_eq!(catalog.skipped_rows, 1);
    }

    #[test]
    fn table_without_service_column_is_ignored() {
        let doc = "## host — 100.0.0.1\n\
                   | Column | Meaning |\n\
                   |---|---|\n\
                   | service | runtime identity |";
        let catalog = parse_catalog(doc);
        assert!(catalog.entities.is_empty());
        assert!(catalog.skipped_tables.is_empty());
    }

    #[test]
    fn docker_names_strip_swarm_task_suffix() {
        let names = parse_docker_names("sae-core_api.1.88iyi4qaypwe8\nplain\n");
        assert_eq!(names[0].name, "sae-core_api");
        assert_eq!(names[1].name, "plain");
    }

    #[test]
    fn systemd_units_mark_operator_paths() {
        let out = "hl-infer.service\t/etc/systemd/system/hl-infer.service\n\
                   dbus.service\t/usr/lib/systemd/system/dbus.service\n";
        let units = parse_systemd_units(out);
        assert_eq!(units[0].name, "hl-infer");
        assert!(units[0].operator);
        assert!(!units[1].operator);
    }

    #[test]
    fn ss_processes_extract_owner_names() {
        let out = "LISTEN 0 4096 127.0.0.1:9090 0.0.0.0:* users:((\"steniorec\",pid=1,fd=9))\n";
        let procs = parse_ss_processes(out);
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].name, "steniorec");
    }

    // ── Invariants ──────────────────────────────────────────────────────────

    #[test]
    fn declared_and_observed_pair_passes() {
        let catalog = catalog_of(vec![declared("h", "steniorec", DeclKind::Container)]);
        let obs = vec![Observation::observed("h", "docker_names", &["steniorec"])];
        let (v, _) = reconcile_all(&catalog, "cat.md", &obs, &no_alias());
        assert!(v.is_empty(), "expected no violations, got {v:?}");
    }

    #[test]
    fn observed_only_fires_exactly_one_reality_undeclared() {
        let catalog = catalog_of(vec![declared("h", "steniorec", DeclKind::Container)]);
        let obs = vec![Observation::observed(
            "h",
            "docker_names",
            &["steniorec", "ghost"],
        )];
        let (v, _) = reconcile_all(&catalog, "cat.md", &obs, &no_alias());
        let hits: Vec<_> = v
            .iter()
            .filter(|x| x.rule_id == REALITY_UNDECLARED)
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].snippet, "ghost");
    }

    #[test]
    fn declared_only_fires_exactly_one_declaration_stale() {
        let catalog = catalog_of(vec![
            declared("h", "steniorec", DeclKind::Container),
            declared("h", "comfyui", DeclKind::Container),
        ]);
        let obs = vec![Observation::observed("h", "docker_names", &["steniorec"])];
        let (v, _) = reconcile_all(&catalog, "cat.md", &obs, &no_alias());
        let hits: Vec<_> = v
            .iter()
            .filter(|x| x.rule_id == DECLARATION_STALE)
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line_number, 1);
    }

    #[test]
    fn exempt_marker_suppresses_stale() {
        let mut ent = declared("h", "dnscrypt", DeclKind::Container);
        ent.exempt = true;
        let catalog = catalog_of(vec![ent]);
        let obs = vec![Observation::observed("h", "docker_names", &["steniorec"])];
        let (v, _) = reconcile_all(&catalog, "cat.md", &obs, &no_alias());
        assert!(!v.iter().any(|x| x.rule_id == DECLARATION_STALE));
    }

    #[test]
    fn missing_purpose_or_owner_fires_purpose_missing() {
        let mut ent = declared("h", "steniorec", DeclKind::Container);
        ent.owner_present = false;
        let catalog = catalog_of(vec![ent]);
        let obs = vec![Observation::observed("h", "docker_names", &["steniorec"])];
        let (v, _) = reconcile_all(&catalog, "cat.md", &obs, &no_alias());
        let hits: Vec<_> = v.iter().filter(|x| x.rule_id == PURPOSE_MISSING).collect();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].message.contains("owner"));
    }

    #[test]
    fn unreadable_source_is_skipped_not_flagged() {
        let catalog = catalog_of(vec![declared("h", "steniorec", DeclKind::Container)]);
        let obs = vec![Observation::skipped("h", "docker_names", "SSH timeout")];
        let (v, notes) = reconcile_all(&catalog, "cat.md", &obs, &no_alias());
        assert!(v.is_empty());
        assert!(notes.iter().any(|n| n.contains("SSH timeout")));
    }

    #[test]
    fn suffix_shorthand_covers_family_members() {
        let catalog = catalog_of(vec![declared(
            "h",
            "miracena-postgres / -mariadb / -redis",
            DeclKind::Container,
        )]);
        let obs = vec![Observation::observed(
            "h",
            "docker_names",
            &["miracena-postgres", "miracena-mariadb", "miracena-redis"],
        )];
        let (v, _) = reconcile_all(&catalog, "cat.md", &obs, &no_alias());
        assert!(v.is_empty(), "expected no violations, got {v:?}");
    }

    #[test]
    fn alias_maps_declared_name_to_observed_name() {
        let catalog = catalog_of(vec![declared("h", "waydroid", DeclKind::Native)]);
        let obs = vec![Observation::observed(
            "h",
            "systemd_units",
            &["waydroid-container"],
        )];
        let mut aliases = HashMap::new();
        aliases.insert("waydroid".to_string(), "waydroid-container".to_string());
        let (v, _) = reconcile_all(&catalog, "cat.md", &obs, &aliases);
        assert!(v.is_empty(), "expected no violations, got {v:?}");
    }

    #[test]
    fn staleness_requires_the_matching_kind_to_be_observed() {
        // A declared native entity is not stale when only docker was observed.
        let catalog = catalog_of(vec![declared("h", "wol-relay", DeclKind::Native)]);
        let obs = vec![Observation::observed("h", "docker_names", &["steniorec"])];
        let (v, _) = reconcile_all(&catalog, "cat.md", &obs, &no_alias());
        assert!(!v.iter().any(|x| x.rule_id == DECLARATION_STALE));
    }

    // ── Policy ──────────────────────────────────────────────────────────────

    #[test]
    fn hujson_comments_and_trailing_commas_parse() {
        let doc = r#"{
  // a comment
  "grants": [
    {"src": ["*"], "dst": ["*"], "ip": ["*"]}, // inline
    {"src": ["autogroup:member"], "dst": ["100.115.253.109"], "app": {"tailscale.com/cap/relay": [],},},
  ],
}"#;
        let grants = parse_policy_grants(doc).expect("huJSON must parse");
        assert_eq!(grants.len(), 2);
        assert!(grants[1].has_app);
    }

    #[test]
    fn allow_all_grant_is_underivable() {
        let doc = r#"{"grants": [{"src": ["*"], "dst": ["*"], "ip": ["*"]}]}"#;
        let grants = parse_policy_grants(doc).expect("parse");
        let ips: BTreeSet<String> = ["100.82.51.112".to_string()].into_iter().collect();
        let v = check_policy(&grants, &ips, &RouteIndex::default(), "policy.hujson");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule_id, POLICY_UNDERIVABLE);
    }

    #[test]
    fn peer_relay_grant_is_derivable() {
        let doc = r#"{"grants": [{"src": ["autogroup:member"], "dst": ["100.115.253.109", "100.124.146.77"], "app": {"tailscale.com/cap/relay": []}}]}"#;
        let grants = parse_policy_grants(doc).expect("parse");
        let ips: BTreeSet<String> = ["100.115.253.109".to_string(), "100.124.146.77".to_string()]
            .into_iter()
            .collect();
        let v = check_policy(&grants, &ips, &RouteIndex::default(), "policy.hujson");
        assert!(v.is_empty());
    }

    #[test]
    fn grant_to_undeclared_host_is_underivable() {
        let doc =
            r#"{"grants": [{"src": ["autogroup:member"], "dst": ["100.9.9.9"], "ip": ["443"]}]}"#;
        let grants = parse_policy_grants(doc).expect("parse");
        let ips: BTreeSet<String> = BTreeSet::new();
        let v = check_policy(&grants, &ips, &RouteIndex::default(), "policy.hujson");
        assert_eq!(v.len(), 1);
        assert!(v[0].message.contains("undeclared host"));
    }

    #[test]
    fn route_grant_requires_documented_cidr() {
        let doc = r#"{"grants": [{"src": ["autogroup:member"], "dst": ["192.168.3.0/24"], "ip": ["443"]}]}"#;
        let grants = parse_policy_grants(doc).expect("parse");
        let mut routes = RouteIndex::default();
        routes.cidrs.insert("192.168.3.0/24".to_string());
        let v = check_policy(&grants, &BTreeSet::new(), &routes, "policy.hujson");
        assert!(v.is_empty());

        let v2 = check_policy(
            &grants,
            &BTreeSet::new(),
            &RouteIndex::default(),
            "policy.hujson",
        );
        assert_eq!(v2.len(), 1);
        assert!(v2[0].message.contains("undocumented route"));
    }

    #[test]
    fn documented_routing_grant_keeps_ip_wildcard() {
        // Exit node: `autogroup:internet` + `ip: *` is the documented pattern.
        let exit = r#"{"grants": [{"src": ["autogroup:member"], "dst": ["autogroup:internet"], "ip": ["*"]}]}"#;
        let grants = parse_policy_grants(exit).expect("parse");
        assert!(check_policy(&grants, &BTreeSet::new(), &RouteIndex::default(), "p").is_empty());

        // Subnet route: `ip: *` is inherent once the CIDR is documented.
        let subnet = r#"{"grants": [{"src": ["autogroup:member"], "dst": ["192.168.3.0/24"], "ip": ["*"]}]}"#;
        let grants = parse_policy_grants(subnet).expect("parse");
        let mut routes = RouteIndex::default();
        routes.cidrs.insert("192.168.3.0/24".to_string());
        assert!(check_policy(&grants, &BTreeSet::new(), &routes, "p").is_empty());
    }

    #[test]
    fn ip_wildcard_to_a_service_tag_is_underivable() {
        let doc =
            r#"{"grants": [{"src": ["autogroup:member"], "dst": ["tag:server"], "ip": ["*"]}]}"#;
        let grants = parse_policy_grants(doc).expect("parse");
        let v = check_policy(&grants, &BTreeSet::new(), &RouteIndex::default(), "p");
        assert_eq!(v.len(), 1);
        assert!(v[0].message.contains("every port/protocol"));
    }

    #[test]
    fn unparsable_policy_is_an_error_not_a_violation() {
        assert!(parse_policy_grants("{ not: valid huJSON ][").is_err());
    }
}
