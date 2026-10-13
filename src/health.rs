use anyhow::Result;
use colored::*;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

pub fn run_system_health() -> Result<()> {
    crate::baseline::print_banner(
        "StenioKernel — Infrastructure Health Snapshot & Services Health (--health)",
    );

    // 1. Disk Storage
    println!(
        "{}",
        "── 💾 Disk Storage ────────────────────────────────────────────────────".dimmed()
    );
    check_disk_health("/", "System Root");
    check_disk_health("/mnt/NVME_PCI", "NVMe PCI (Workspace & Caches)");
    println!();

    // 2. RAM Memory & Swap
    println!(
        "{}",
        "── 🧠 Physical Memory & Host Resources ─────────────────────────────────".dimmed()
    );
    check_memory_health();
    println!();

    // 3. GPU & Blackwell Acceleration
    println!(
        "{}",
        "── ⚡ Graphics Acceleration & VRAM ─────────────────────────────────────".dimmed()
    );
    check_gpu_health();
    println!();

    // 4. Services & Local Connectivity
    println!(
        "{}",
        "── 🔌 Hub Services & Network Ports ─────────────────────────────────────".dimmed()
    );
    check_tcp_service("PostgreSQL", "127.0.0.1", 5432, "Relational Database SQLx");
    check_tcp_service("Valkey / Redis", "127.0.0.1", 6379, "Event Bus & Cache");
    check_http_service(
        "stenio-server",
        "http://127.0.0.1:9090",
        "Rust Server Axum + Whisper",
    );
    check_frontend_parity();
    println!();

    // 5. Canonical Homelab Backup Chain (/mnt/BACKUP)
    println!(
        "{}",
        "── 🛡️ Backup Chain & NAS Integrity (/mnt/BACKUP) ───────────────────────".dimmed()
    );
    check_backup_chain();
    println!();

    // 6. Tailscale Mesh & OS Heterogeneity
    println!(
        "{}",
        "── 🌐 Tailscale Mesh & Operating Systems (Mnemocine Homelab) ───────────".dimmed()
    );
    if let Ok(rt) = tokio::runtime::Runtime::new() {
        let results = rt.block_on(crate::mesh::audit_tailscale_mesh());
        let mut online_count = 0;
        for res in &results {
            let status_badge = if res.is_online {
                online_count += 1;
                let lat_str = crate::mesh::format_latency(res.latency);
                format!("ONLINE ({})", lat_str).green().bold()
            } else {
                "OFFLINE".red().bold()
            };
            let os_shell = format!("{}/{}", res.node.os, res.node.shell);
            println!(
                "   {:<15} [{:<15}] - {:<20} | {:<16} | {}",
                res.node.name.bold(),
                res.node.ip.dimmed(),
                status_badge,
                os_shell.cyan(),
                res.node.role.dimmed()
            );
        }
        println!();
        println!(
            "   Mesh Status: {} of {} nodes active and connected.",
            online_count,
            results.len()
        );
    }
    println!();

    // 7. Docker Infrastructure & Image Hygiene
    println!(
        "{}",
        "── 🐳 Docker Infrastructure & Image Hygiene ────────────────────────────".dimmed()
    );
    check_docker_health();
    println!();

    // 8. Port Gatekeeper & Attack Surface Management
    println!(
        "{}",
        "── 🚪 Port Gatekeeper & Attack Surface Management ──────────────────────".dimmed()
    );
    check_ports_health();
    println!();

    println!(
        "{}",
        "✨ Diagnostic complete. Infrastructure ready for operation."
            .green()
            .bold()
    );
    println!();

    Ok(())
}

fn check_backup_chain() {
    let backup_dir = std::path::Path::new("/mnt/BACKUP");
    if !backup_dir.is_dir() {
        println!(
            "   {:<25} - {}",
            "NAS /mnt/BACKUP".bold(),
            "Not mounted or inaccessible".red().bold()
        );
        return;
    }

    let targets = [
        ("configs-homelab", "Git Mirror + Configs of All Nodes"),
        (
            "zomboid-server-kavure",
            "Game Data / Saves / Configs (Kavure)",
        ),
        ("sumaenima-server-kavure", "Borg Backups / Sumænimá Hub DB"),
        (
            "agentic-ai-server-psicopompo",
            "Nightly Obsidian Vault Snapshot",
        ),
        (
            "monitoring-server-kavure",
            "Prometheus Metrics & Grafana Dashboards",
        ),
    ];

    for (folder, desc) in targets {
        let p = backup_dir.join(folder);
        if p.exists() {
            // Source of truth for freshness = job health file (/srv/health),
            // not payload mtime (rsync preserves source mtime -> false "old").
            let host_dir = p.join("psicopompo");
            let mod_time = find_matching_health_file(folder).or_else(|| most_recent_mtime(&p));
            let mod_time = if mod_time.is_none() {
                // fallback: host subdir when mirror uses {host}/ (configs-homelab)
                if host_dir.exists() {
                    most_recent_mtime(&host_dir)
                } else {
                    None
                }
            } else {
                mod_time
            };
            let age_str = if let Some(m) = mod_time {
                let elapsed_secs = m.elapsed().map(|d| d.as_secs()).unwrap_or(0);
                let hours = elapsed_secs / 3600;
                if hours < 24 {
                    format!("Intact (updated {}h ago)", hours).green().bold()
                } else {
                    format!("Warning (>{}h without update)", hours)
                        .yellow()
                        .bold()
                }
            } else {
                "Present".green().bold()
            };
            println!(
                "   {:<30} - {:<30} [{}]",
                folder.bold(),
                age_str,
                desc.dimmed()
            );
        } else {
            println!(
                "   {:<30} - {:<30} [{}]",
                folder.bold(),
                "MISSING".red().bold(),
                desc.dimmed()
            );
        }
    }

    // Git push of mirror -> private GitHub mnemocine (versioned off-site).
    let mirror = backup_dir.join("configs-homelab");
    let mirror_synced = Command::new("git")
        .args([
            "-C",
            mirror.to_str().unwrap_or("/mnt/BACKUP/configs-homelab"),
            "status",
            "-sb",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            let behind = s.contains("behind");
            let ahead = s.contains("ahead");
            let diverged = behind && ahead;
            if diverged {
                "DIVERGED local×remote (manual push + timer conflict)".to_string()
            } else if ahead {
                "AHEAD — local changes not yet pushed (05:55 timer pending)".to_string()
            } else if behind {
                "BEHIND — remote has commits not present locally".to_string()
            } else {
                "SYNCED with GitHub (push OK)".to_string()
            }
        })
        .unwrap_or_else(|_| "Could not inspect git".to_string());
    let synced_ok = mirror_synced.contains("SYNCED");
    println!(
        "   {:<30} - {:<30} [{}]",
        "git push (GitHub)".bold(),
        if synced_ok {
            mirror_synced.green().bold()
        } else {
            mirror_synced.yellow().bold()
        },
        "Versioned off-site".dimmed()
    );
}

/// Matches backup target directory with corresponding job health file (/srv/health/)
/// — standard: health file = {prefix}-last-ok; Grafana relies on these as source of truth.
fn find_matching_health_file(target_folder: &str) -> Option<std::time::SystemTime> {
    let prefix = match target_folder {
        "configs-homelab" => "config-backup-psicopompo",
        "agentic-ai-server-psicopompo" => "agentic-ai-backup",
        "zomboid-server-kavure" => "zomboid-backup",
        "monitoring-server-kavure" => "monitoring-backup",
        "sumaenima-server-kavure" => "sumaenima-backup",
        _ => return None,
    };
    let dir = std::path::Path::new("/srv/health");
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name == format!("{}-last-ok", prefix) {
                if let Ok(md) = e.metadata() {
                    if let Ok(t) = md.modified() {
                        return Some(t);
                    }
                }
            }
        }
    }
    None
}

/// mtime of the most recent item inside the directory — true freshness proxy
/// (mirror root does not change in rsync, only subdirs per host).
/// Recursively descends up to 4 levels (mirrors contain nested payloads: daily/prometheus/<ts>/chunks).
fn most_recent_mtime(dir: &std::path::Path) -> Option<std::time::SystemTime> {
    let mut best: Option<std::time::SystemTime> = None;
    let mut stack: Vec<std::path::PathBuf> = vec![dir.to_path_buf()];
    let mut depth: std::collections::HashMap<std::path::PathBuf, usize> =
        std::collections::HashMap::new();
    depth.insert(dir.to_path_buf(), 0);
    while let Some(p) = stack.pop() {
        let d = depth.get(&p).copied().unwrap_or(0);
        if d > 4 {
            continue;
        }
        if let Ok(entries) = fs::read_dir(&p) {
            for e in entries.flatten() {
                let path = e.path();
                if let Ok(md) = e.metadata() {
                    if md.is_file() {
                        if let Ok(t) = md.modified() {
                            best = Some(match best {
                                Some(b) if b >= t => b,
                                _ => t,
                            });
                        }
                    } else if md.is_dir() {
                        depth.insert(path.clone(), d + 1);
                        stack.push(path);
                    }
                }
            }
        }
    }
    best
}

fn check_disk_health(path: &str, label: &str) {
    use std::ffi::CString;
    use std::mem::MaybeUninit;

    let c_path = match CString::new(path) {
        Ok(c) => c,
        Err(_) => {
            println!(
                "   {:<30} [{}] - {}",
                label.bold(),
                path.cyan(),
                "INVALID PATH".red()
            );
            return;
        }
    };

    let mut stat = MaybeUninit::<libc::statvfs>::uninit();
    let res = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };

    if res == 0 {
        let stat = unsafe { stat.assume_init() };
        let block_size = stat.f_frsize as f64;
        let total_bytes = stat.f_blocks as f64 * block_size;
        let free_bytes = stat.f_bavail as f64 * block_size;

        if total_bytes > 0.0 {
            let used_bytes = total_bytes - free_bytes;
            let pct = (used_bytes / total_bytes) * 100.0;
            let total_gb = total_bytes / (1024.0 * 1024.0 * 1024.0);
            let free_gb = free_bytes / (1024.0 * 1024.0 * 1024.0);

            let status = if pct > 90.0 {
                format!("CRITICAL ({:.0}% used)", pct).red().bold()
            } else if pct > 75.0 {
                format!("WARNING ({:.0}% used)", pct).yellow().bold()
            } else {
                format!("HEALTHY ({:.0}% used)", pct).green().bold()
            };

            println!(
                "   {:<30} [{}] - {:.1} GB free of {:.1} GB ({})",
                label.bold(),
                path.cyan(),
                free_gb,
                total_gb,
                status
            );
            return;
        }
    }

    println!(
        "   {:<30} [{}] - {}",
        label.bold(),
        path.cyan(),
        "Could not inspect".yellow()
    );
}

fn check_memory_health() {
    if let Ok(content) = fs::read_to_string("/proc/meminfo") {
        let mut total_kb: f64 = 0.0;
        let mut avail_kb: f64 = 0.0;

        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                total_kb = parse_meminfo_line(line);
            } else if line.starts_with("MemAvailable:") {
                avail_kb = parse_meminfo_line(line);
            }
        }

        if total_kb > 0.0 {
            let used_kb = total_kb - avail_kb;
            let used_pct = (used_kb / total_kb) * 100.0;
            let total_gb = total_kb / (1024.0 * 1024.0);
            let avail_gb = avail_kb / (1024.0 * 1024.0);

            let status = if used_pct > 90.0 {
                format!("{:.1}% in use", used_pct).red().bold()
            } else {
                format!("{:.1}% in use", used_pct).green().bold()
            };

            println!(
                "   {:<30} {:.1} GB available of {:.1} GB ({})",
                "Total RAM Memory".bold(),
                avail_gb,
                total_gb,
                status
            );
            return;
        }
    }
    println!(
        "   {:<30} {}",
        "RAM Memory".bold(),
        "Not available".yellow()
    );
}

fn parse_meminfo_line(line: &str) -> f64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0)
}

fn check_gpu_health() {
    let output = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,driver_version,memory.total,memory.free",
            "--format=csv,noheader,nounits",
        ])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some(first_line) = stdout.lines().next() {
                let parts = crate::util::csv_fields(first_line);
                if parts.len() >= 4 {
                    let name = parts[0];
                    let driver = parts[1];
                    let total = parts[2];
                    let free = parts[3];
                    println!(
                        "   {:<30} {} (Driver {}) | VRAM: {} MiB free / {} MiB total",
                        "NVIDIA GPU".bold(),
                        name.cyan().bold(),
                        driver,
                        free.green().bold(),
                        total
                    );
                    return;
                }
            }
        }
    }
    println!(
        "   {:<30} {}",
        "Physical GPU".bold(),
        "Not detected or no active NVIDIA driver".yellow()
    );
}

fn check_tcp_service(name: &str, host: &str, port: u16, role: &str) {
    let t0 = Instant::now();
    let addr_str = format!("{}:{}", host, port);
    let socket_addr: Result<SocketAddr, _> = addr_str.parse();

    let online = if let Ok(addr) = socket_addr {
        TcpStream::connect_timeout(&addr, Duration::from_millis(150)).is_ok()
    } else {
        false
    };

    let elapsed = t0.elapsed().as_millis();
    if online {
        println!(
            "   {:<20} :{:<5} [{}] - {} ({} ms)",
            name.bold(),
            port,
            role.dimmed(),
            "ONLINE".green().bold(),
            elapsed
        );
    } else {
        println!(
            "   {:<20} :{:<5} [{}] - {}",
            name.bold(),
            port,
            role.dimmed(),
            "OFFLINE (idle)".dimmed()
        );
    }
}

/// Fetches a URL body with the `xh` HTTP client — the Rust client already used
/// for the service probes — with a 1s timeout. `None` means the request could
/// not be completed (client missing, connection refused, timeout, or an HTTP
/// error status, since `xh` runs with `--check-status`). Callers therefore
/// degrade gracefully instead of failing their whole audit.
pub fn http_get_body(url: &str) -> Option<String> {
    let output = Command::new("xh")
        .args(["get", url, "-b", "--timeout=1"])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        None
    }
}

pub fn http_get_health(url: &str) -> Option<(bool, u128)> {
    let t0 = Instant::now();
    let body = http_get_body(&format!("{}/v1/health", url))?;
    let elapsed = t0.elapsed().as_millis();
    Some((
        body.contains("\"status\"") && body.contains("\"ok\""),
        elapsed,
    ))
}

fn check_http_service(name: &str, url: &str, role: &str) {
    if let Some((is_ok, elapsed)) = http_get_health(url) {
        if is_ok {
            println!(
                "   {:<20} {:<6} [{}] - {} ({} ms)",
                name.bold(),
                ":9090",
                role.dimmed(),
                "ONLINE / HEALTHY".green().bold(),
                elapsed
            );
            return;
        }
    }
    println!(
        "   {:<20} {:<6} [{}] - {}",
        name.bold(),
        ":9090",
        role.dimmed(),
        "OFFLINE (idle)".dimmed()
    );
}

fn check_frontend_parity() {
    let root = std::path::Path::new(".");
    if let Some(parity) = crate::deploy::check_static_parity(root) {
        let status_badge = if parity.in_sync {
            format!("PARITY OK ({})", parity.local_bundle)
                .green()
                .bold()
        } else {
            format!(
                "DRIFT DETECTED (local: {}, edge: {})",
                parity.local_bundle, parity.remote_bundle
            )
            .yellow()
            .bold()
        };
        println!(
            "   {:<20} {:<6} [{}] - {}",
            "frontend-v2".bold(),
            ":443",
            "Edge Ybyra vs Local Build".dimmed(),
            status_badge
        );
    }
}

fn check_docker_health() {
    let output = match Command::new("docker")
        .args(["system", "df", "--format", "{{json .}}"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => {
            println!(
                "   {:<25} - {}",
                "Docker Daemon".bold(),
                "Inactive or not installed".dimmed()
            );
            return;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut total_reclaimable = 0u64;

    for line in stdout.lines() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            let row_type = val.get("Type").and_then(|v| v.as_str()).unwrap_or("");
            let total = val
                .get("TotalCount")
                .and_then(|v| v.as_str())
                .unwrap_or("0");
            let active = val.get("Active").and_then(|v| v.as_str()).unwrap_or("0");
            let size = val.get("Size").and_then(|v| v.as_str()).unwrap_or("0B");
            let reclaimable = val
                .get("Reclaimable")
                .and_then(|v| v.as_str())
                .unwrap_or("0B");

            let rec_bytes = crate::clean::parse_docker_size(reclaimable);
            total_reclaimable += rec_bytes;

            let badge = if rec_bytes > 1024 * 1024 * 1024 {
                format!("{} ({})", size.bold(), reclaimable.yellow().bold())
            } else {
                format!("{} ({})", size.bold(), reclaimable.dimmed())
            };

            println!(
                "   {:<25} [{:>2} active / {:>2} total] - {}",
                format!("Docker {}", row_type).bold(),
                active.green().bold(),
                total.white(),
                badge
            );
        }
    }

    if total_reclaimable > 1024 * 1024 * 1024 {
        println!(
            "   ⚠️  {} accumulated in dangling images/cache. Tip: use '{}' to clean.",
            crate::clean::format_bytes(total_reclaimable)
                .yellow()
                .bold(),
            "stenio --clean docker".cyan().bold()
        );
    } else {
        println!(
            "   ✨ Docker sanitized and lean ({:.2} MiB reclaimable).",
            total_reclaimable as f64 / (1024.0 * 1024.0)
        );
    }
}

/// Decides whether one observed socket is an attack-surface alert for the local
/// host, using the **same** verdict as the `--ports` auditor.
///
/// The catalog, the accepted `0.0.0.0` exceptions (parsed from §4 of the matrix)
/// and the wildcard-bind predicate all come from `ports.rs` — the auditor is the
/// single source of truth (HB-054). This wrapper only adds the two *uncatalogued*
/// dispositions the auditor renders inline: loopback is never an exposure, and
/// the client/ephemeral desktop range is expected. `--health` and `--ports` can
/// therefore never disagree on the same live state.
fn is_attack_surface_alert(
    sock: &crate::ports::ActiveSocket,
    catalog_map: &std::collections::HashMap<u16, Vec<&crate::ports::PortEntry>>,
    exceptions: &crate::ports::PortExceptions,
) -> bool {
    if let Some(entry) = catalog_map
        .get(&sock.port)
        .and_then(|entries| entries.iter().find(|e| e.host == "psicopompo"))
    {
        return crate::ports::is_unauthorized_wildcard_bind(sock, entry, exceptions);
    }

    if sock.ip.starts_with("127.0.0.") || sock.ip == "::1" {
        return false;
    }

    !(sock.port > 30000 || sock.port == 1716 || sock.port == 27036 || sock.port == 9863)
}

fn check_ports_health() {
    let root = std::path::Path::new(".");
    let sockets = crate::ports::scan_local_active_sockets();
    let catalog = crate::ports::load_port_catalog(root);
    let exceptions = crate::ports::load_port_exceptions(root);

    let mut catalog_map: std::collections::HashMap<u16, Vec<&crate::ports::PortEntry>> =
        std::collections::HashMap::new();
    for entry in &catalog {
        catalog_map.entry(entry.port).or_default().push(entry);
    }

    let mut open_count = 0;
    let mut warn_count = 0;
    let mut seen = std::collections::HashSet::new();

    for sock in &sockets {
        if !seen.insert(sock.port) {
            continue;
        }
        open_count += 1;
        if is_attack_surface_alert(sock, &catalog_map, &exceptions) {
            warn_count += 1;
        }
    }

    if warn_count == 0 {
        println!(
            "   ✨ {} active mapped ports. Attack surface 100% compliant with canonical catalog.",
            open_count.to_string().green().bold()
        );
    } else {
        println!(
            "   ⚠️  {} active ports ({} anomaly/anomalies or 0.0.0.0 bind detected). Use '{}' to audit.",
            open_count.to_string().yellow().bold(),
            warn_count.to_string().red().bold(),
            "stenio --ports".cyan().bold()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{ActiveSocket, PortEntry, PortExceptions};

    fn entry(host: &str, port: u16, proto: &str, bind: &str, defect: bool) -> PortEntry {
        PortEntry {
            host: host.into(),
            port,
            proto: proto.into(),
            bind: bind.into(),
            service: "svc".into(),
            justification: if defect {
                "exposed. **⚠️ defect**".into()
            } else {
                "documented".into()
            },
            doc_link: "doc".into(),
            defect,
        }
    }

    fn socket(ip: &str, port: u16, proto: &str) -> ActiveSocket {
        ActiveSocket {
            proto: proto.into(),
            ip: ip.into(),
            port,
            process: None,
        }
    }

    /// HB-054 regression: the old heuristic excused 2049/111/20048 by hardcoded
    /// port number and flagged any catalogued wildcard whose §2 text mentioned
    /// `tailscale0`. Here the §4-parsed exceptions decide: an unexcepted wildcard
    /// (20048 absent from §4) is an alert, an excepted one (22000 in §4) is not.
    #[test]
    fn verdict_follows_the_parsed_section_four_exceptions() {
        let entries = vec![
            entry("psicopompo", 20048, "tcp", "LAN (`0.0.0.0`)", false),
            entry("psicopompo", 22000, "tcp", "LAN + `tailscale0`", false),
        ];
        let mut map: std::collections::HashMap<u16, Vec<&PortEntry>> =
            std::collections::HashMap::new();
        for e in &entries {
            map.entry(e.port).or_default().push(e);
        }

        let mut exceptions = PortExceptions::default();
        exceptions.insert(22000, "tcp");

        assert!(is_attack_surface_alert(
            &socket("0.0.0.0", 20048, "tcp"),
            &map,
            &exceptions
        ));
        assert!(!is_attack_surface_alert(
            &socket("0.0.0.0", 22000, "tcp"),
            &map,
            &exceptions
        ));
    }

    /// The catalogued verdict is delegated verbatim to the auditor's predicate —
    /// the parity the alignment guarantees (no parallel heuristic).
    #[test]
    fn catalogued_verdict_matches_the_auditor_predicate() {
        let entries = vec![
            entry("psicopompo", 11470, "tcp", "0.0.0.0", true),
            entry("psicopompo", 9095, "tcp", "127.0.0.1", false),
        ];
        let mut map: std::collections::HashMap<u16, Vec<&PortEntry>> =
            std::collections::HashMap::new();
        for e in &entries {
            map.entry(e.port).or_default().push(e);
        }
        let exceptions = PortExceptions::default();

        for e in &entries {
            let sock = socket("0.0.0.0", e.port, "tcp");
            let expected = crate::ports::is_unauthorized_wildcard_bind(&sock, e, &exceptions);
            assert_eq!(is_attack_surface_alert(&sock, &map, &exceptions), expected);
        }
    }

    /// Uncatalogued dispositions mirror the auditor: loopback and the
    /// client/ephemeral range are expected; a low uncatalogued port is an orphan.
    #[test]
    fn uncatalogued_dispositions_match_the_auditor() {
        let map: std::collections::HashMap<u16, Vec<&PortEntry>> = std::collections::HashMap::new();
        let exceptions = PortExceptions::default();

        assert!(!is_attack_surface_alert(
            &socket("127.0.0.1", 49374, "tcp"),
            &map,
            &exceptions
        ));
        assert!(!is_attack_surface_alert(
            &socket("0.0.0.0", 43653, "tcp"),
            &map,
            &exceptions
        ));
        assert!(is_attack_surface_alert(
            &socket("100.82.51.112%tailscale0", 443, "tcp"),
            &map,
            &exceptions
        ));
    }

    /// A catalogued port whose row belongs to another host falls back to the
    /// uncatalogued disposition, exactly like the auditor's `node_entry` lookup.
    #[test]
    fn other_host_rows_do_not_mask_a_local_orphan() {
        let entries = vec![entry("kavure", 443, "tcp", "0.0.0.0", false)];
        let mut map: std::collections::HashMap<u16, Vec<&PortEntry>> =
            std::collections::HashMap::new();
        for e in &entries {
            map.entry(e.port).or_default().push(e);
        }
        assert!(is_attack_surface_alert(
            &socket("100.82.51.112%tailscale0", 443, "tcp"),
            &map,
            &PortExceptions::default()
        ));
    }
}
