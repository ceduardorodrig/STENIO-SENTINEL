use anyhow::Result;
use colored::*;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PortEntry {
    pub host: String,
    pub port: u16,
    pub proto: String,
    pub bind: String,
    pub service: String,
    pub justification: String,
    pub doc_link: String,
    /// True when §2 marks this row as a live `0.0.0.0` defect (`⚠️ defect`).
    ///
    /// This is the document's own reality-audit marker (§2 preamble): a socket
    /// that is genuinely exposed is a defect, so a §4 exception must not excuse
    /// it on that host. Reading the marker keeps the engine data-driven — adding
    /// or fixing a host row in `ports.md` changes the verdict with no code edit.
    pub defect: bool,
}

/// Accepted wildcard-bind exceptions declared by §4 of the canonical matrix.
///
/// The set is parsed from `mnemocine/network/ports.md` (§4 "Legitimate `0.0.0.0`
/// Exceptions"), never hardcoded: registering or revoking an exception is a
/// documentation edit, not an engine change.
#[derive(Debug, Clone, Default)]
pub struct PortExceptions {
    keys: std::collections::HashSet<(u16, String)>,
}

impl PortExceptions {
    /// Registers `(port, proto)` as an accepted `0.0.0.0` exception.
    pub fn insert(&mut self, port: u16, proto: &str) {
        self.keys.insert((port, proto.trim().to_ascii_lowercase()));
    }

    /// True when §4 declares `(port, proto)` an accepted `0.0.0.0` exception.
    pub fn contains(&self, port: u16, proto: &str) -> bool {
        self.keys
            .contains(&(port, proto.trim().to_ascii_lowercase()))
    }
}

#[derive(Debug, Clone)]
pub struct ActiveSocket {
    pub proto: String,
    pub ip: String,
    pub port: u16,
    pub process: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PortClassification {
    AuthorizedOnline,
    AuthorizedOffline,
    LocalEphemeral,
    OrphanUncataloged,
    SecurityExposureWarning,
}

/// Resolves and reads the canonical port matrix (`mnemocine/network/ports.md`),
/// falling back to the absolute vault path when run from another directory.
fn read_port_matrix(root: &Path) -> Option<String> {
    let candidates = [
        root.join("mnemocine/network/ports.md"),
        Path::new("/mnt/NVME_PCI/agentic-ai/mnemocine/network/ports.md").to_path_buf(),
    ];

    candidates
        .iter()
        .find(|path| path.is_file())
        .and_then(|path| fs::read_to_string(path).ok())
}

/// Loads the Canonical Port Catalog from mnemocine/network/ports.md
pub fn load_port_catalog(root: &Path) -> Vec<PortEntry> {
    if let Some(content) = read_port_matrix(root) {
        let entries = parse_markdown_catalog(&content);
        if !entries.is_empty() {
            return entries;
        }
    }

    fallback_catalog()
}

/// Loads the accepted `0.0.0.0` exceptions from §4 of the canonical matrix.
///
/// Returns an empty set when the matrix (or its §4 table) is unavailable, which
/// only makes the audit stricter — no exception is silently invented.
pub fn load_port_exceptions(root: &Path) -> PortExceptions {
    read_port_matrix(root)
        .map(|content| parse_exception_table(&content))
        .unwrap_or_default()
}

/// Parses §4 ("Legitimate `0.0.0.0` Exceptions") from the canonical matrix.
///
/// The table is located by its heading and read until the next `##` heading.
/// Only the first (Port) column is consumed, so the free-text justification —
/// which itself contains backticked port numbers — can never leak into the set.
/// Each token is a `port[,port…]/proto[,proto…]` spec and every combination is
/// registered, covering rows such as `` `47992/47993/tcp` `` and
/// `` `7946/tcp,udp` `` without hardcoding a single port or service name.
pub fn parse_exception_table(content: &str) -> PortExceptions {
    let mut exceptions = PortExceptions::default();
    let mut in_section = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## ") {
            // Enter §4 on its own heading and leave on the next section.
            in_section = trimmed.contains("Exception");
            continue;
        }
        if !in_section || !trimmed.starts_with('|') {
            continue;
        }

        let cells: Vec<&str> = trimmed.split('|').collect();
        let Some(port_cell) = cells.get(1) else {
            continue;
        };
        for token in backticked_tokens(port_cell) {
            for (port, proto) in parse_port_token(&token) {
                exceptions.insert(port, &proto);
            }
        }
    }

    exceptions
}

/// Extracts every backtick-delimited token from a table cell.
fn backticked_tokens(cell: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut open = false;

    for ch in cell.chars() {
        match ch {
            '`' => {
                if open {
                    tokens.push(std::mem::take(&mut current));
                    open = false;
                } else {
                    current.clear();
                    open = true;
                }
            }
            _ if open => current.push(ch),
            _ => {}
        }
    }

    tokens
}

/// Expands a `port[,port…]/proto[,proto…]` token into `(port, proto)` pairs.
///
/// Examples: `9777/udp` → one pair; `7946/tcp,udp` → two; `47992/47993/tcp` →
/// two. A malformed token yields nothing rather than a panic.
fn parse_port_token(token: &str) -> Vec<(u16, String)> {
    let parts: Vec<&str> = token.split('/').collect();
    if parts.len() < 2 {
        return Vec::new();
    }

    let protos: Vec<String> = parts[parts.len() - 1]
        .split(',')
        .map(|proto| proto.trim().to_ascii_lowercase())
        .filter(|proto| !proto.is_empty())
        .collect();

    let mut pairs = Vec::new();
    for segment in &parts[..parts.len() - 1] {
        for raw_port in segment.split(',') {
            if let Ok(port) = raw_port.trim().parse::<u16>() {
                for proto in &protos {
                    pairs.push((port, proto.clone()));
                }
            }
        }
    }

    pairs
}

/// Parses the Markdown ports table
fn parse_markdown_catalog(content: &str) -> Vec<PortEntry> {
    let mut entries = Vec::new();
    let mut current_host = "psicopompo".to_string();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("### 2.1. Psicopompo") {
            current_host = "psicopompo".to_string();
        } else if trimmed.starts_with("### 2.2. Kavure") {
            current_host = "kavure".to_string();
        } else if trimmed.starts_with("### 2.3. Ybyra") {
            current_host = "ybyra".to_string();
        } else if trimmed.starts_with("### 2.4. Ybytu") {
            current_host = "ybytu".to_string();
        } else if trimmed.starts_with("### 2.5. Kuaray") {
            current_host = "kuaray".to_string();
        }

        if trimmed.starts_with('|') && (trimmed.contains("/tcp") || trimmed.contains("/udp")) {
            let cols: Vec<&str> = trimmed.split('|').map(|c| c.trim()).collect();
            if cols.len() >= 6 {
                let raw_port_proto = cols[1].replace('`', "");
                let bind = cols[2].replace('`', "");
                let service = cols[3].replace(['*', '`'], "");
                let justification = cols[4].to_string();
                let doc_link = cols[5].to_string();
                // §2 marks a genuinely exposed socket with `⚠️ defect`; that
                // marker survives a §4 exception (the exception is not valid on
                // a host whose own row is a known defect).
                let defect = justification.contains("⚠️ defect");

                let (port_str, proto) = if raw_port_proto.contains('/') {
                    let mut parts = raw_port_proto.splitn(2, '/');
                    (parts.next().unwrap_or(""), parts.next().unwrap_or("tcp"))
                } else {
                    (raw_port_proto.as_str(), "tcp")
                };

                // Supports comma-separated ports (e.g. 80, 443)
                for p_sub in port_str.split(',') {
                    if let Ok(p_num) = p_sub.trim().parse::<u16>() {
                        entries.push(PortEntry {
                            host: current_host.clone(),
                            port: p_num,
                            proto: proto.trim().to_string(),
                            bind: bind.clone(),
                            service: service.clone(),
                            justification: justification.clone(),
                            doc_link: doc_link.clone(),
                            defect,
                        });
                    }
                }
            }
        }
    }

    entries
}

/// Embedded canonical fallback in case the catalog file is not found
fn fallback_catalog() -> Vec<PortEntry> {
    vec![
        PortEntry {
            host: "psicopompo".into(),
            port: 9090,
            proto: "tcp".into(),
            bind: "100.82.51.112:9090".into(),
            service: "steniorec (Axum/Whisper)".into(),
            justification: "GPU inference for audio and STT streaming".into(),
            doc_link: "mnemocine/network/service-topology.md".into(),
            defect: false,
        },
        PortEntry {
            host: "psicopompo".into(),
            port: 8384,
            proto: "tcp".into(),
            bind: "127.0.0.1 / 100.82.51.112".into(),
            service: "Syncthing Web GUI".into(),
            justification: "Syncthing administrative web interface".into(),
            doc_link: "mnemocine/backups/".into(),
            defect: false,
        },
        PortEntry {
            host: "psicopompo".into(),
            port: 22000,
            proto: "tcp,udp".into(),
            bind: "LAN / tailscale0".into(),
            service: "Syncthing Sync".into(),
            justification: "Node-to-node data synchronization".into(),
            doc_link: "mnemocine/backups/".into(),
            defect: false,
        },
        PortEntry {
            host: "psicopompo".into(),
            port: 2049,
            proto: "tcp,udp".into(),
            bind: "LAN / tailscale0".into(),
            service: "NFSv4 Server".into(),
            justification: "NAS file sharing".into(),
            doc_link: "mnemocine/network/nfs.md".into(),
            defect: false,
        },
        PortEntry {
            host: "psicopompo".into(),
            port: 61208,
            proto: "tcp".into(),
            bind: "tailscale0".into(),
            service: "Glances".into(),
            justification: "Resource telemetry".into(),
            doc_link: "mnemocine/network/service-topology.md".into(),
            defect: false,
        },
        PortEntry {
            host: "psicopompo".into(),
            port: 9100,
            proto: "tcp".into(),
            bind: "tailscale0".into(),
            service: "Node Exporter".into(),
            justification: "Prometheus metrics".into(),
            doc_link: "mnemocine/services/".into(),
            defect: false,
        },
        PortEntry {
            host: "kavure".into(),
            port: 5432,
            proto: "tcp".into(),
            bind: "100.124.146.77".into(),
            service: "PostgreSQL (sae-core_db)".into(),
            justification: "Relational database".into(),
            doc_link: "mnemocine/services/database.md".into(),
            defect: false,
        },
        PortEntry {
            host: "kavure".into(),
            port: 6379,
            proto: "tcp".into(),
            bind: "100.124.146.77".into(),
            service: "Valkey (sae-core_valkey)".into(),
            justification: "Cache and event messaging".into(),
            doc_link: "mnemocine/services/valkey.md".into(),
            defect: false,
        },
        PortEntry {
            host: "kavure".into(),
            port: 9090,
            proto: "tcp".into(),
            bind: "100.124.146.77".into(),
            service: "sae-core_api".into(),
            justification: "Sumænimá Hub Core API".into(),
            doc_link: "mnemocine/services/core-api.md".into(),
            defect: false,
        },
    ]
}

/// Scans actively listening sockets on local machine via ss
pub fn scan_local_active_sockets() -> Vec<ActiveSocket> {
    let output = match Command::new("ss").args(["-Htlpn"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ss_output(&stdout)
}

/// Parses tabular output of ss command (-Htlpn or -tlpn)
pub fn parse_ss_output(stdout: &str) -> Vec<ActiveSocket> {
    let mut sockets = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("State") || trimmed.starts_with("Netid") {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() >= 4 {
            // In ss -Htlpn or -tlpn with State Recv-Q Send-Q Local Address:Port Peer Address:Port
            let addr_col = if cols[0] == "LISTEN" && cols.len() >= 4 {
                cols[3]
            } else if cols.len() >= 4 && cols[0].starts_with("tcp") || cols[0].starts_with("udp") {
                cols[4]
            } else {
                cols[3]
            };

            let (ip, port) = parse_addr(addr_col);
            if port > 0 {
                let proc_name = if line.contains("users:((") {
                    line.split("users:((\"")
                        .nth(1)
                        .and_then(|s| s.split('"').next())
                        .map(|s| s.to_string())
                } else {
                    None
                };

                sockets.push(ActiveSocket {
                    proto: "tcp".to_string(),
                    ip,
                    port,
                    process: proc_name,
                });
            }
        }
    }
    sockets
}

fn parse_addr(addr: &str) -> (String, u16) {
    if let Some(pos) = addr.rfind(':') {
        let ip_part = &addr[..pos];
        let port_part = &addr[pos + 1..];
        let clean_ip = ip_part.trim_matches('[').trim_matches(']');
        let clean_ip = if clean_ip == "*" || clean_ip.is_empty() {
            "0.0.0.0"
        } else {
            clean_ip
        };
        let port = port_part.parse::<u16>().unwrap_or(0);
        (clean_ip.to_string(), port)
    } else {
        ("0.0.0.0".to_string(), 0)
    }
}

/// True when an observed bind listens on every interface.
///
/// `ss` renders a wildcard IPv4 bind as `0.0.0.0`, a wildcard IPv6 bind as `::`
/// and some kernels/tools as `*`; all three are the same exposure.
pub fn is_wildcard_bind(ip: &str) -> bool {
    matches!(ip, "0.0.0.0" | "::" | "*")
}

/// Decides whether a *catalogued* listening socket is an unauthorized bind.
///
/// The verdict follows the **observed** bind, never the catalog wording: a socket
/// actually listening on `0.0.0.0`/`::`/`*` is a defect unless §4 of the matrix
/// declares its `(port, proto)` an accepted exception **and** the host's own §2
/// row is not itself flagged as a `⚠️ defect`. Because §4 is host-agnostic data
/// and the defect marker is per host, an exception accepted locally (psicopompo)
/// is also accepted remotely (kavure/ybyra/ybytu) — while a host that the matrix
/// marks exposed (e.g. kavure's Swarm ports) is never excused.
pub fn is_unauthorized_wildcard_bind(
    sock: &ActiveSocket,
    entry: &PortEntry,
    exceptions: &PortExceptions,
) -> bool {
    is_wildcard_bind(&sock.ip) && !(exceptions.contains(sock.port, &sock.proto) && !entry.defect)
}

fn print_port_table_row(
    indent: &str,
    port_proto: impl std::fmt::Display,
    ip_bind: impl std::fmt::Display,
    service_proc: impl std::fmt::Display,
    verdict: impl std::fmt::Display,
    doc_desc: impl std::fmt::Display,
) {
    println!(
        "{indent}{:<10} [{:<15}] {:<22} | {} | {}",
        port_proto, ip_bind, service_proc, verdict, doc_desc
    );
}

fn render_active_socket(
    indent: &str,
    sock: &ActiveSocket,
    node_name: &str,
    catalog_map: &HashMap<u16, Vec<&PortEntry>>,
    exceptions: &PortExceptions,
    alerts_count: &mut usize,
) {
    let proc_label = sock.process.as_deref().unwrap_or("system / docker").cyan();
    let entries_for_port = catalog_map.get(&sock.port);
    let node_entry = entries_for_port.and_then(|v| v.iter().find(|e| e.host == node_name));

    if let Some(entry) = node_entry {
        if is_unauthorized_wildcard_bind(sock, entry, exceptions) {
            *alerts_count += 1;
            print_port_table_row(
                indent,
                format!("{}/{}", sock.port, sock.proto).yellow().bold(),
                sock.ip.red().bold(),
                entry.service.white().bold(),
                "⚠️ UNAUTHORIZED BIND 0.0.0.0".red().bold(),
                entry.doc_link.dimmed(),
            );
        } else {
            print_port_table_row(
                indent,
                format!("{}/{}", sock.port, sock.proto).green().bold(),
                sock.ip.dimmed(),
                entry.service.white().bold(),
                "COMPLIANT".green().bold(),
                entry.doc_link.dimmed(),
            );
        }
    } else if sock.ip.starts_with("127.0.0.") || sock.ip == "::1" {
        print_port_table_row(
            indent,
            format!("{}/{}", sock.port, sock.proto).dimmed(),
            sock.ip.dimmed(),
            proc_label,
            "LOCALHOST / TEMPORARY DEV".dimmed(),
            "Not exposed to external network".dimmed(),
        );
    } else if node_name == "psicopompo"
        && (sock.port > 30000 || sock.port == 1716 || sock.port == 27036 || sock.port == 9863)
    {
        print_port_table_row(
            indent,
            format!("{}/{}", sock.port, sock.proto).blue(),
            sock.ip.dimmed(),
            proc_label,
            "CLIENT / EPHEMERAL DESKTOP".blue(),
            "Local application usage".dimmed(),
        );
    } else if node_name != "psicopompo" && (sock.port > 30000 || sock.port == 22) {
        let label = if sock.port == 22 {
            "SSH DAEMON"
        } else {
            "CLIENT / EPHEMERAL DESKTOP"
        };
        print_port_table_row(
            indent,
            format!("{}/{}", sock.port, sock.proto).blue(),
            sock.ip.dimmed(),
            proc_label,
            label.blue(),
            "Management / application access".dimmed(),
        );
    } else {
        *alerts_count += 1;
        print_port_table_row(
            indent,
            format!("{}/{}", sock.port, sock.proto).red().bold(),
            sock.ip.yellow().bold(),
            proc_label,
            "UNCATALOGED ORPHAN PORT".red().bold(),
            "Register in mnemocine/network/ports.md".yellow(),
        );
    }
}

fn render_offline_ports<T>(
    indent: &str,
    catalog: &[PortEntry],
    host_name: &str,
    active_ports: &HashMap<u16, T>,
) {
    for entry in catalog {
        if entry.host == host_name && !active_ports.contains_key(&entry.port) {
            print_port_table_row(
                indent,
                format!("{}/{}", entry.port, entry.proto).dimmed(),
                entry.bind.dimmed(),
                entry.service.dimmed(),
                "IDLE / OFFLINE".dimmed(),
                entry.doc_link.dimmed(),
            );
        }
    }
}

/// Runs full Port Gatekeeper audit (Attack Surface Management)
pub async fn run_ports_audit(root: &Path) -> Result<()> {
    crate::baseline::print_banner(
        "StenioKernel — Port Gatekeeper & Attack Surface Management (--ports)",
    );

    let catalog = load_port_catalog(root);
    let exceptions = load_port_exceptions(root);
    let local_sockets = scan_local_active_sockets();

    let mut catalog_map: HashMap<u16, Vec<&PortEntry>> = HashMap::new();
    for entry in &catalog {
        catalog_map.entry(entry.port).or_default().push(entry);
    }

    // ── 1. Local Host Audit (Psicopompo) ─────────────────────────────────────
    println!(
        "{}",
        "── 🛡️ Local Host: Psicopompo (100.82.51.112) — Active Sockets & Compliance ──".dimmed()
    );

    let mut active_ports_found = HashMap::new();
    let mut alerts_count = 0;

    for sock in &local_sockets {
        // Avoid duplicate identical IPv4/IPv6 binds
        if active_ports_found.contains_key(&sock.port) {
            continue;
        }
        active_ports_found.insert(sock.port, sock);

        render_active_socket(
            "   ",
            sock,
            "psicopompo",
            &catalog_map,
            &exceptions,
            &mut alerts_count,
        );
    }

    // List cataloged ports that are idle (offline)
    render_offline_ports("   ", &catalog, "psicopompo", &active_ports_found);

    println!();

    // ── 2. Remote Homelab Nodes Audit via Tailscale & SSH ────────────────────
    println!(
        "{}",
        "── 🌐 Remote Homelab Nodes Audit via Tailscale & SSH ─────────────────────".dimmed()
    );

    let remote_nodes = [
        ("kavure", "100.124.146.77"),
        ("ybyra", "100.66.224.34"),
        ("ybytu", "100.115.253.109"),
        ("kuaray", "100.94.209.99"),
    ];

    for (node_name, ip) in remote_nodes {
        println!(
            "   [{}] {} ({})",
            "NODE".cyan().bold(),
            node_name.bold(),
            ip.dimmed()
        );

        // 1. Try SSH for internal health snapshot with Tailscale re-auth detection
        let outcome =
            crate::remote::run_ssh(node_name, "sudo -n ss -Htlpn 2>/dev/null || ss -Htlpn", 4);

        let mut ssh_success = false;

        match outcome {
            crate::remote::RemoteOutcome::Success(ref stdout_str) if !stdout_str.is_empty() => {
                let sockets = parse_ss_output(stdout_str);

                if !sockets.is_empty() {
                    ssh_success = true;
                    let mut node_active_ports = HashMap::new();

                    for sock in &sockets {
                        if node_active_ports.contains_key(&sock.port) {
                            continue;
                        }
                        node_active_ports.insert(sock.port, sock.clone());

                        render_active_socket(
                            "      ",
                            sock,
                            node_name,
                            &catalog_map,
                            &exceptions,
                            &mut alerts_count,
                        );
                    }

                    // Report cataloged ports at rest on remote node
                    render_offline_ports("      ", &catalog, node_name, &node_active_ports);
                }
            }
            crate::remote::RemoteOutcome::AuthRequired { ref auth_url, .. } => {
                println!(
                    "      ⚠️  {} {}",
                    "TAILSCALE SSH AUTHENTICATION REQUIRED:".yellow().bold(),
                    auth_url.cyan().underline().bold()
                );
                println!(
                    "         {}",
                    "👉 Open the link above in your browser to authorize SSH access to this node."
                        .dimmed()
                );
            }
            _ => {}
        }

        // 2. If SSH is unresponsive or failed, transparent fallback to TCP Probing
        if !ssh_success {
            println!(
                "      {}",
                "ℹ️  SSH unavailable or pending — running direct TCP probing via Tailnet..."
                    .dimmed()
            );

            let node_catalog_entries: Vec<&PortEntry> =
                catalog.iter().filter(|e| e.host == node_name).collect();

            for entry in node_catalog_entries {
                let addr = format!("{}:{}", ip, entry.port);
                let t0 = std::time::Instant::now();
                let status =
                    match timeout(Duration::from_millis(400), TcpStream::connect(&addr)).await {
                        Ok(Ok(_stream)) => {
                            let lat = t0.elapsed();
                            format!(
                                "{} ({:.1}ms)",
                                "OPEN / ONLINE".green().bold(),
                                lat.as_secs_f64() * 1000.0
                            )
                        }
                        Ok(Err(_e)) => "CLOSED / IDLE".dimmed().to_string(),
                        Err(_) => "TIMEOUT / BLOCKED".yellow().dimmed().to_string(),
                    };

                println!(
                    "      {:<10} {:<24} - {}",
                    format!(":{}", entry.port).white().bold(),
                    entry.service.dimmed(),
                    status
                );
            }
        }
    }

    println!();
    println!(
        "{}",
        "──────────────────────────────────────────────────────────────────────────────".dimmed()
    );

    if alerts_count == 0 {
        println!(
            "{}",
            "✨ Attack surface 100% mapped and compliant with the port catalog."
                .green()
                .bold()
        );
    } else {
        println!(
            "⚠️  Detected {} anomaly/anomalies or uncataloged ports. Review the table above.",
            alerts_count.to_string().yellow().bold()
        );
    }
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a catalog row; `defect` mirrors the document's `⚠️ defect` marker.
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

    /// Blind spot 1 (pre-fix regression): a socket documented *truthfully* as
    /// `0.0.0.0` rendered `COMPLIANT` because the catalog text lacked
    /// `127.0.0.1`/`tailscale0`/`100.`. Concrete case: psicopompo Stremio.
    #[test]
    fn truthful_wildcard_bind_absent_from_section_four_is_flagged() {
        let stremio = entry("psicopompo", 11470, "tcp", "0.0.0.0", true);
        let sock = socket("0.0.0.0", 11470, "tcp");
        assert!(is_unauthorized_wildcard_bind(
            &sock,
            &stremio,
            &PortExceptions::default()
        ));
    }

    /// The observed bind decides, never the wording: even a row the document did
    /// not mark as a defect is a finding when it listens on `0.0.0.0` and §4
    /// never accepted it (e.g. a `LAN (0.0.0.0)` row such as rpc.mountd).
    #[test]
    fn non_defect_wildcard_bind_absent_from_section_four_is_still_flagged() {
        let mountd = entry("psicopompo", 20048, "tcp", "LAN (`0.0.0.0`)", false);
        let sock = socket("0.0.0.0", 20048, "tcp");
        assert!(is_unauthorized_wildcard_bind(
            &sock,
            &mountd,
            &PortExceptions::default()
        ));
    }

    /// Blind spot 2 (pre-fix regression): the remote branch ignored §4, so an
    /// accepted exception (kavure `:8123`) rendered `UNAUTHORIZED`.
    #[test]
    fn section_four_exception_is_accepted_on_a_remote_host() {
        let mut exceptions = PortExceptions::default();
        exceptions.insert(8123, "tcp");
        let ha = entry("kavure", 8123, "tcp", "0.0.0.0 (host networking)", false);
        let sock = socket("0.0.0.0", 8123, "tcp");
        assert!(!is_unauthorized_wildcard_bind(&sock, &ha, &exceptions));
    }

    /// Do not weaken: §4 lists the Swarm raft port, but kavure's own row is a
    /// defect (no host firewall), so the exception must not excuse it.
    #[test]
    fn section_four_does_not_excuse_a_host_marked_as_a_defect() {
        let mut exceptions = PortExceptions::default();
        exceptions.insert(2377, "tcp");
        let swarm = entry("kavure", 2377, "tcp", "0.0.0.0", true);
        let sock = socket("0.0.0.0", 2377, "tcp");
        assert!(is_unauthorized_wildcard_bind(&sock, &swarm, &exceptions));
    }

    /// An exception is protocol-specific: `9777/udp` does not excuse a tcp bind.
    #[test]
    fn section_four_exception_is_protocol_specific() {
        let mut exceptions = PortExceptions::default();
        exceptions.insert(9777, "udp");
        let punktfunk = entry("psicopompo", 9777, "tcp", "0.0.0.0", false);
        let sock = socket("0.0.0.0", 9777, "tcp");
        assert!(is_unauthorized_wildcard_bind(
            &sock,
            &punktfunk,
            &exceptions
        ));
    }

    /// A restricted observed bind stays compliant even without an exception.
    #[test]
    fn restricted_observed_bind_is_compliant() {
        let valkey = entry(
            "kavure",
            6379,
            "tcp",
            "sae-net (Overlay — unexposed on host)",
            false,
        );
        let sock = socket("100.124.146.77", 6379, "tcp");
        assert!(!is_unauthorized_wildcard_bind(
            &sock,
            &valkey,
            &PortExceptions::default()
        ));
    }

    /// §4 parsing: only the Port column counts, multi-port and multi-proto
    /// tokens expand, and backticked numbers in the justification are ignored.
    #[test]
    fn parses_section_four_exception_table() {
        let doc = "\
## 3. Role\n\
| `1/tcp` | not-an-exception |\n\
## 4. Legitimate `0.0.0.0` Exceptions\n\
\n\
| Port | Service | Technical Justification |\n\
|---|---|---|\n\
| `9777/udp`, `47990/tcp`, `47992/47993/tcp` | **Punktfunk** | binds `0.0.0.0` |\n\
| `2377/tcp`, `4789/udp`, `7946/tcp,udp`, `9092/tcp` | **Swarm** | raft port (`2377`), gossip (`7946`) |\n\
| `3001/tcp`, `3002/tcp`, `9100/tcp` | **Ybytu** | allow list (`9096`) |\n\
## 5. Next\n\
| `5555/tcp` | not-an-exception |\n";

        let exceptions = parse_exception_table(doc);
        for (port, proto) in [
            (9777u16, "udp"),
            (47990, "tcp"),
            (47992, "tcp"),
            (47993, "tcp"),
            (2377, "tcp"),
            (4789, "udp"),
            (7946, "tcp"),
            (7946, "udp"),
            (9092, "tcp"),
            (3001, "tcp"),
            (3002, "tcp"),
            (9100, "tcp"),
        ] {
            assert!(exceptions.contains(port, proto), "missing {port}/{proto}");
        }
        assert!(!exceptions.contains(1, "tcp"));
        assert!(!exceptions.contains(5555, "tcp"));
        assert!(!exceptions.contains(8123, "udp"));
    }

    /// The catalog parser reads the document's own `⚠️ defect` marker per row.
    #[test]
    fn catalog_parser_marks_defect_rows() {
        let doc = "\
### 2.1. Psicopompo\n\
| Port / Proto | Bind Interface | Service | Technical Justification | Canonical Reference |\n\
|---|---|---|---|---|\n\
| `11470,12470/tcp` | `0.0.0.0` | **Stremio** | Embedded node server. **⚠️ defect** — must bind `127.0.0.1` | [`x`](x) |\n\
| `9090/tcp` | `127.0.0.1` | **steniorec** | GPU transcription | [`x`](x) |\n";

        let entries = parse_markdown_catalog(doc);
        assert!(entries.iter().any(|e| e.port == 11470 && e.defect));
        assert!(entries.iter().any(|e| e.port == 12470 && e.defect));
        assert!(entries.iter().any(|e| e.port == 9090 && !e.defect));
    }
}
