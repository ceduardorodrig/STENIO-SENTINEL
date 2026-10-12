//! Audits operational tools against what the repository versions.
//!
//! # Why it exists
//!
//! Operational tools (`config-backup`, `zomboid-*`, `smart-metrics`, …)
//! previously existed **only** in `/usr/local/bin`, outside any repository.
//! The governance engine audits repository files — never the live filesystem —
//! so it was unable to see them.
//!
//! # How it works
//!
//! The source of truth is the repository itself: the operational tools live under a
//! tools root (e.g. `provisioning/`) with `scripts/` (operational tools) and
//! `<crate>/` (Rust tools). The installer `install-homelab-tools.sh` maintains the
//! map of known tools — which this auditor reads to ensure parity.
//!
//! The catalog is **discovered, never hardcoded**: the installer is located by an
//! explicit `STENIO_TOOLS_CATALOG` override or by a bounded, gitignore-aware search
//! of the repository tree, so the layout can change (or move to another repository)
//! without an engine change.
//!
//! | State | Verdict |
//! |---|---|
//! | Present on host AND repo | ✅ compliant |
//! | Present on host and NOT in repo | ⚠️ **orphan** — migration candidate |
//! | Third-party binary / system package | ignored by allowlist |

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Third-party binaries and system packages that legitimately reside in
/// `/usr/local/bin` without belonging to this ecosystem codebase.
const ALLOWLIST: &[&str] = &[
    "bat",
    "fd",
    "apt",
    "gnome-help",
    "yelp",
    "highlight-mint",
    "search",
    "ollama",
    "mkinitcpio",
    "remove-nvidia",
];

/// Rust binaries whose crates are versioned in OTHER repository paths (not in
/// `provisioning/scripts/` because they are compiled binaries).
const KNOWN_ELSEWHERE: &[&str] = &["gpu-supervisor", "with-smooth-motion"];

struct Report {
    hosts: Vec<HostResult>,
}

struct HostResult {
    host: String,
    /// Tools present on the host.
    present: BTreeSet<String>,
    /// Tools declared and versioned in the repository.
    declared: BTreeSet<String>,
    /// Error accessing the host, if any.
    error: Option<String>,
}

impl HostResult {
    /// Tools on the host unknown to the repository — the primary audit finding.
    fn orphans(&self) -> Vec<&String> {
        self.present
            .iter()
            .filter(|f| !self.declared.contains(*f))
            .collect()
    }

    /// Declared tools missing on the host.
    fn missing(&self) -> Vec<&String> {
        self.declared
            .iter()
            .filter(|f| !self.present.contains(*f))
            .collect()
    }
}

pub fn run_tools_audit(repo_root: &Path) -> anyhow::Result<()> {
    println!();
    println!("══════════════════════════════════════════════════════════════════════════════");
    println!("  🧰 StenioKernel — Operation Tools Audit (--tools)");
    println!("══════════════════════════════════════════════════════════════════════════════");
    println!("  Cross-checks /usr/local/bin of each host with the repository tools catalog.");
    println!("  Orphan = exists on host but not in repository (untracked, unreviewed).");
    println!();

    let declared = read_declared_tools(repo_root);
    if declared.is_empty() {
        println!("  ⚠️  No declared tools found — no tools catalog in this repository.");
        println!("     Expected: an `install-homelab-tools.sh` somewhere in the tree, or set");
        println!("     the `STENIO_TOOLS_CATALOG` environment variable to its path (file or");
        println!("     the tools root that contains `scripts/`).");
        println!("     Without this catalog, host × repository cross-checking is impossible.");
        println!();
        return Ok(());
    }
    let root_label = find_tools_catalog(repo_root)
        .and_then(|p| {
            tools_root(&p)
                .strip_prefix(repo_root)
                .ok()
                .map(|r| r.display().to_string())
        })
        .unwrap_or_else(|| ".".to_string());
    println!(
        "  Source of truth: {}/ ({} declared tools)",
        root_label.trim_end_matches('/'),
        declared.len()
    );
    println!();

    let hosts = ["psicopompo", "kavure", "kuaray", "ybyra", "ybytu"];
    let mut report = Report { hosts: Vec::new() };

    for host in hosts {
        let present = list_host_tools(host);
        let (present, error) = match present {
            Ok(p) => (p, None),
            Err(e) => (BTreeSet::new(), Some(e)),
        };
        report.hosts.push(HostResult {
            host: host.to_string(),
            present,
            declared: declared.clone(),
            error,
        });
    }

    let mut total_orphans = 0usize;
    for h in &report.hosts {
        print_host(h);
        total_orphans += h.orphans().len();
    }

    println!("──────────────────────────────────────────────────────────────────────────────");
    if total_orphans == 0 {
        println!("  ✅ Zero orphan tools: entire operational suite is version-controlled.");
        println!("     Everything running in /usr/local/bin exists in the tools catalog,");
        println!("     enforcing automated gates, reviews, and git history.");
    } else {
        println!(
            "  ⚠️  {total_orphans} orphan tool(s) detected — untracked, unreviewed, invisible to gate."
        );
        println!("     Migrate it into the tools catalog and install via");
        println!("     `install-homelab-tools.sh` (see mnemocine/guides/stenio-ci-unificado.md).");
    }
    println!();

    Ok(())
}

fn print_host(h: &HostResult) {
    println!("  [NODE] {}", h.host);
    if let Some(err) = &h.error {
        println!("       ✗ unreachable: {err}");
        return;
    }

    let orphans = h.orphans();
    if orphans.is_empty() {
        println!("       ✅ all present tools are version-controlled");
    } else {
        for o in orphans {
            println!("       ⚠️  {o} — NOT versioned (migration candidate)");
        }
    }

    // Declared tools missing on host: can be normal (each host has a distinct role),
    // so this is informative and not an alert.
    let missing = h.missing();
    if !missing.is_empty() {
        println!(
            "       ℹ️  {} declared and absent on this node (normal: host role)",
            missing.len()
        );
    }
}

/// Lists tools in `/usr/local/bin`, filtering allowlist and backups.
///
/// Locally uses `std::fs`; remotely uses the canonical driver
/// `crate::remote::run_ssh` — mandatory by rule `RUST-CANONICAL-REMOTE`,
/// which exists to enforce timeout isolation, `BatchMode`, and Tailscale SSH
/// re-auth detection in a single place.
fn list_host_tools(host: &str) -> Result<BTreeSet<String>, String> {
    let is_local = host_matches_local(host);

    let listing = if is_local {
        fs::read_dir("/usr/local/bin")
            .map_err(|e| format!("read_dir: {e}"))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        match crate::remote::run_ssh(host, "ls -1 /usr/local/bin 2>/dev/null", 8) {
            crate::remote::RemoteOutcome::Success(out) => out,
            crate::remote::RemoteOutcome::AuthRequired { .. } => {
                return Err("SSH requires re-authentication (Tailscale check mode)".to_string());
            }
            crate::remote::RemoteOutcome::Timeout { timeout_secs, .. } => {
                return Err(format!("ssh: timeout after {timeout_secs}s"));
            }
            crate::remote::RemoteOutcome::Unreachable { reason, .. } => {
                return Err(format!("ssh unreachable: {reason}"));
            }
            crate::remote::RemoteOutcome::Failed { exit_code, .. } => {
                return Err(format!("ssh failed (exit={exit_code:?})"));
            }
        }
    };

    let mut tools = BTreeSet::new();
    for line in listing.lines() {
        let name = line.trim();
        if name.is_empty() {
            continue;
        }
        if is_ignored(name) {
            continue;
        }
        tools.insert(name.to_string());
    }
    Ok(tools)
}

/// Decides whether a file in `/usr/local/bin` should be ignored in the audit.
fn is_ignored(name: &str) -> bool {
    // Backups deliberately left behind by migrations (documented in commit).
    if name.contains(".bak-") || name.ends_with(".disabled") {
        return true;
    }
    // Third-party binaries / system packages.
    if ALLOWLIST.contains(&name) {
        return true;
    }
    // Crates versioned in other parts of the repository.
    if KNOWN_ELSEWHERE.contains(&name) {
        return true;
    }
    false
}

/// Compares hostname with local node, tolerating casing differences.
fn host_matches_local(host: &str) -> bool {
    let local = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            fs::read_to_string("/proc/sys/kernel/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default()
        .to_ascii_lowercase();
    host.eq_ignore_ascii_case(&local)
}

/// Reads declared tools from the canonical installer.
///
/// The installer maintains two bash maps (`RUST_TOOLS` and `SHELL_TOOLS`). Reading from there —
/// rather than maintaining a parallel list in Rust — guarantees that audit and install
/// never diverge. This is simple line parsing, not a full bash interpreter.
fn read_declared_tools(repo_root: &Path) -> BTreeSet<String> {
    let mut set = BTreeSet::new();

    let Some(installer) = find_tools_catalog(repo_root) else {
        return set;
    };
    let Ok(content) = fs::read_to_string(&installer) else {
        return set;
    };

    for line in content.lines() {
        let t = line.trim();
        // Entry format: `[name]=name`
        if !t.starts_with('[') || !t.contains("]=") {
            continue;
        }
        if let Some(end) = t.find(']') {
            let name = &t[1..end];
            // Ignore `--help` key and flags; names come only from the tool map.
            if !name.is_empty() && !name.starts_with('-') {
                set.insert(name.to_string());
            }
        }
    }

    // Rust tools also have their crate directory as declaration, even if
    // the bash map uses another name. Scan `<tools_root>/*/Cargo.toml`.
    if let Ok(entries) = fs::read_dir(tools_root(&installer)) {
        for e in entries.flatten() {
            let p = e.path();
            if p.join("Cargo.toml").is_file()
                && let Some(name) = p.file_name().and_then(|n| n.to_str())
            {
                set.insert(name.to_string());
            }
        }
    }

    set
}

/// Locates the operational-tools catalog (the installer) **without** assuming a
/// fixed directory layout, so the tools can live under any tools root or in a
/// dedicated repository.
///
/// Resolution order:
///   1. `STENIO_TOOLS_CATALOG` — path to the installer **or** to the tools root
///      (the directory that contains `scripts/`).
///   2. Bounded (depth ≤ 4), gitignore-aware discovery of `install-homelab-tools.sh`
///      anywhere in the repository tree.
fn find_tools_catalog(repo_root: &Path) -> Option<PathBuf> {
    const INSTALLER: &str = "install-homelab-tools.sh";

    if let Some(raw) = std::env::var_os("STENIO_TOOLS_CATALOG") {
        let base = PathBuf::from(raw);
        if base.is_file() {
            return Some(base);
        }
        for rel in [format!("scripts/{INSTALLER}"), INSTALLER.to_string()] {
            let candidate = base.join(rel);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    let walker = ignore::WalkBuilder::new(repo_root)
        .max_depth(Some(4))
        .build();
    for entry in walker.flatten() {
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false)
            && entry.file_name().to_str() == Some(INSTALLER)
        {
            return Some(entry.into_path());
        }
    }
    None
}

/// The tools root = the directory that holds the `scripts/` folder, or the
/// installer's own directory when it is not nested under `scripts/`.
fn tools_root(installer: &Path) -> PathBuf {
    let dir = installer.parent().unwrap_or(Path::new("."));
    if dir.file_name().and_then(|n| n.to_str()) == Some("scripts") {
        dir.parent().unwrap_or(dir).to_path_buf()
    } else {
        dir.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ignores_backups_and_allowlist() {
        assert!(is_ignored("config-backup.bak-20260929"));
        assert!(is_ignored("scryfall-prefetch.disabled"));
        assert!(is_ignored("bat"));
        assert!(is_ignored("fd"));
        assert!(is_ignored("gpu-supervisor"));
        assert!(is_ignored("with-smooth-motion"));
    }

    #[test]
    fn test_does_not_ignore_internal_tools() {
        assert!(!is_ignored("config-backup"));
        assert!(!is_ignored("zomboid-backup"));
        assert!(!is_ignored("smart-metrics"));
    }

    #[test]
    fn test_reads_installer_maps() {
        let dir = std::env::temp_dir().join("stenio-tools-test-nested");
        let scripts = dir.join("provisioning/scripts");
        let _ = fs::create_dir_all(&scripts);
        let _ = fs::write(
            scripts.join("install-homelab-tools.sh"),
            "declare -A SHELL_TOOLS=(\n    [config-backup]=config-backup\n    [zomboid-backup]=zomboid-backup\n)\n",
        );
        let got = read_declared_tools(&dir);
        assert!(got.contains("config-backup"));
        assert!(got.contains("zomboid-backup"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_discovers_flat_layout() {
        // The catalog must be found regardless of the directory layout
        // (e.g. a dedicated repository with `scripts/` at the root).
        let dir = std::env::temp_dir().join("stenio-tools-test-flat");
        let scripts = dir.join("scripts");
        let _ = fs::create_dir_all(&scripts);
        let _ = fs::write(
            scripts.join("install-homelab-tools.sh"),
            "declare -A SHELL_TOOLS=(\n    [netwatch-metrics.sh]=netwatch-metrics.sh\n)\n",
        );
        let got = read_declared_tools(&dir);
        assert!(got.contains("netwatch-metrics.sh"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tools_root_strips_scripts() {
        assert_eq!(
            tools_root(Path::new(
                "/repo/provisioning/scripts/install-homelab-tools.sh"
            )),
            PathBuf::from("/repo/provisioning")
        );
        assert_eq!(
            tools_root(Path::new("/repo/scripts/install-homelab-tools.sh")),
            PathBuf::from("/repo")
        );
    }

    #[test]
    fn test_local_host_recognized_without_ssh() {
        // The current node must be treated as local to avoid relying on SSH.
        let me = std::env::var("HOSTNAME").unwrap_or_default();
        if !me.is_empty() {
            assert!(host_matches_local(&me));
        }
    }
}
