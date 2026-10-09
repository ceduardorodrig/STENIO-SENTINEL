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
//! The source of truth is the repository itself: `provisioning/scripts/` (operational tools)
//! and `provisioning/<crate>/` (Rust tools). The installer `install-homelab-tools.sh`
//! maintains the map of known tools — which this auditor reads to ensure parity.
//!
//! | State | Verdict |
//! |---|---|
//! | Present on host AND repo | ✅ compliant |
//! | Present on host and NOT in repo | ⚠️ **orphan** — migration candidate |
//! | Third-party binary / system package | ignored by allowlist |

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

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
    println!("  Cross-checks /usr/local/bin of each host with repository `provisioning/`.");
    println!("  Orphan = exists on host but not in repository (untracked, unreviewed).");
    println!();

    let declared = read_declared_tools(repo_root);
    if declared.is_empty() {
        println!("  ⚠️  No declared tools found.");
        println!(
            "     Expected: {}/provisioning/scripts/install-homelab-tools.sh",
            repo_root.display()
        );
        println!("     Without this catalog, host × repository cross-checking is impossible.");
        println!();
        return Ok(());
    }
    println!(
        "  Source of truth: provisioning/ ({} declared tools)",
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
        println!("     Everything running in /usr/local/bin exists in provisioning/,");
        println!("     enforcing automated gates, reviews, and git history.");
    } else {
        println!(
            "  ⚠️  {total_orphans} orphan tool(s) detected — untracked, unreviewed, invisible to gate."
        );
        println!("     Migrate to provisioning/scripts/ and install via");
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
    let installer = repo_root.join("provisioning/scripts/install-homelab-tools.sh");
    let mut set = BTreeSet::new();

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
    // the bash map uses another name. Scan `provisioning/*/Cargo.toml`.
    if let Ok(entries) = fs::read_dir(repo_root.join("provisioning")) {
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
        let dir = std::env::temp_dir().join("stenio-tools-test");
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
    fn test_local_host_recognized_without_ssh() {
        // The current node must be treated as local to avoid relying on SSH.
        let me = std::env::var("HOSTNAME").unwrap_or_default();
        if !me.is_empty() {
            assert!(host_matches_local(&me));
        }
    }
}
