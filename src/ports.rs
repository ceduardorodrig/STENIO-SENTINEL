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

/// Carrega o Catálogo Canônico de Portas a partir de mnemocine/network/ports.md
pub fn load_port_catalog(root: &Path) -> Vec<PortEntry> {
    let candidates = [
        root.join("mnemocine/network/ports.md"),
        Path::new("/mnt/NVME_PCI/agentic-ai/mnemocine/network/ports.md").to_path_buf(),
    ];

    for path in &candidates {
        if path.is_file() {
            if let Ok(content) = fs::read_to_string(path) {
                let entries = parse_markdown_catalog(&content);
                if !entries.is_empty() {
                    return entries;
                }
            }
        }
    }

    fallback_catalog()
}

/// Faz o parsing da tabela Markdown de portas
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

                let (port_str, proto) = if raw_port_proto.contains('/') {
                    let mut parts = raw_port_proto.splitn(2, '/');
                    (parts.next().unwrap_or(""), parts.next().unwrap_or("tcp"))
                } else {
                    (raw_port_proto.as_str(), "tcp")
                };

                // Suporta portas com vírgula (ex: 80, 443)
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
                        });
                    }
                }
            }
        }
    }

    entries
}

/// Fallback canônico embutido caso o arquivo de catálogo não seja encontrado
fn fallback_catalog() -> Vec<PortEntry> {
    vec![
        PortEntry {
            host: "psicopompo".into(),
            port: 9090,
            proto: "tcp".into(),
            bind: "100.82.51.112:9090".into(),
            service: "steniorec (Axum/Whisper)".into(),
            justification: "Inferência GPU de áudio e streaming STT".into(),
            doc_link: "mnemocine/network/service-topology.md".into(),
        },
        PortEntry {
            host: "psicopompo".into(),
            port: 8384,
            proto: "tcp".into(),
            bind: "127.0.0.1 / 100.82.51.112".into(),
            service: "Syncthing Web GUI".into(),
            justification: "Interface administrativa do Syncthing".into(),
            doc_link: "mnemocine/backups/".into(),
        },
        PortEntry {
            host: "psicopompo".into(),
            port: 22000,
            proto: "tcp,udp".into(),
            bind: "LAN / tailscale0".into(),
            service: "Syncthing Sync".into(),
            justification: "Sincronização de dados entre nós".into(),
            doc_link: "mnemocine/backups/".into(),
        },
        PortEntry {
            host: "psicopompo".into(),
            port: 2049,
            proto: "tcp,udp".into(),
            bind: "LAN / tailscale0".into(),
            service: "NFSv4 Server".into(),
            justification: "Compartilhamento de arquivos do NAS".into(),
            doc_link: "mnemocine/network/nfs.md".into(),
        },
        PortEntry {
            host: "psicopompo".into(),
            port: 61208,
            proto: "tcp".into(),
            bind: "tailscale0".into(),
            service: "Glances".into(),
            justification: "Telemetria de recursos".into(),
            doc_link: "mnemocine/network/service-topology.md".into(),
        },
        PortEntry {
            host: "psicopompo".into(),
            port: 9100,
            proto: "tcp".into(),
            bind: "tailscale0".into(),
            service: "Node Exporter".into(),
            justification: "Métricas Prometheus".into(),
            doc_link: "mnemocine/services/".into(),
        },
        PortEntry {
            host: "kavure".into(),
            port: 5432,
            proto: "tcp".into(),
            bind: "100.124.146.77".into(),
            service: "PostgreSQL (sae-core_db)".into(),
            justification: "Banco de dados relacional".into(),
            doc_link: "mnemocine/services/database.md".into(),
        },
        PortEntry {
            host: "kavure".into(),
            port: 6379,
            proto: "tcp".into(),
            bind: "100.124.146.77".into(),
            service: "Valkey (sae-core_valkey)".into(),
            justification: "Cache e mensageria de eventos".into(),
            doc_link: "mnemocine/services/valkey.md".into(),
        },
        PortEntry {
            host: "kavure".into(),
            port: 9090,
            proto: "tcp".into(),
            bind: "100.124.146.77".into(),
            service: "sae-core_api".into(),
            justification: "API Core do Sumænimá Hub".into(),
            doc_link: "mnemocine/services/core-api.md".into(),
        },
    ]
}

/// Escaneia sockets ouvindo ativamente na máquina local via ss
pub fn scan_local_active_sockets() -> Vec<ActiveSocket> {
    let mut sockets = Vec::new();

    let output = match Command::new("ss").args(["-Htlpn"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return sockets,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 {
            let addr_col = cols[3];
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

/// Executa a auditoria completa do Porteiro das Portas (Attack Surface Management)
pub async fn run_ports_audit(root: &Path) -> Result<()> {
    crate::baseline::print_banner("StênioKernel — Porteiro das Portas & Superfície de Ataque (--ports)");

    let catalog = load_port_catalog(root);
    let local_sockets = scan_local_active_sockets();

    let mut catalog_map: HashMap<u16, Vec<&PortEntry>> = HashMap::new();
    for entry in &catalog {
        catalog_map.entry(entry.port).or_default().push(entry);
    }

    // ── 1. Auditoria do Host Local (Psicopompo) ──────────────────────────────
    println!(
        "{}",
        "── 🛡️ Host Local: Psicopompo (100.82.51.112) — Sockets Ativos & Conformidade ──".dimmed()
    );

    let mut active_ports_found = HashMap::new();
    let mut alerts_count = 0;

    for sock in &local_sockets {
        // Evita duplicatas de bind IPv4/IPv6 idênticas
        if active_ports_found.contains_key(&sock.port) {
            continue;
        }
        active_ports_found.insert(sock.port, sock);

        let proc_label = sock
            .process
            .as_deref()
            .unwrap_or("sistema / docker")
            .cyan();

        let entries_for_port = catalog_map.get(&sock.port);
        let psicopompo_entry = entries_for_port.and_then(|v| {
            v.iter().find(|e| e.host == "psicopompo")
        });

        if let Some(entry) = psicopompo_entry {
            // Verificar se o bind é seguro
            let is_wide_open = sock.ip == "0.0.0.0" || sock.ip == "::";
            let should_be_restricted = entry.bind.contains("127.0.0.1") || entry.bind.contains("tailscale0") || entry.bind.contains("100.");

            if is_wide_open && should_be_restricted && entry.port != 2049 && entry.port != 111 && entry.port != 20048 {
                // Alerta de exposição
                alerts_count += 1;
                println!(
                    "   {:<10} [{:<15}] {:<22} | {} | {}",
                    format!("{}/{}", sock.port, sock.proto).yellow().bold(),
                    sock.ip.red().bold(),
                    entry.service.white().bold(),
                    "⚠️ BIND 0.0.0.0 NÃO AUTORIZADO".red().bold(),
                    entry.doc_link.dimmed()
                );
            } else {
                println!(
                    "   {:<10} [{:<15}] {:<22} | {} | {}",
                    format!("{}/{}", sock.port, sock.proto).green().bold(),
                    sock.ip.dimmed(),
                    entry.service.white().bold(),
                    "CONFORME".green().bold(),
                    entry.doc_link.dimmed()
                );
            }
        } else if sock.ip.starts_with("127.0.0.") || sock.ip == "::1" {
            // Localhost / Dev temporário
            println!(
                "   {:<10} [{:<15}] {:<22} | {} | {}",
                format!("{}/{}", sock.port, sock.proto).dimmed(),
                sock.ip.dimmed(),
                proc_label,
                "LOCALHOST / DEV TEMPORÁRIO".dimmed(),
                "Não exposto à rede externa".dimmed()
            );
        } else if sock.port > 30000 || sock.port == 1716 || sock.port == 27036 || sock.port == 9863 {
            // Cliente desktop / efêmero
            println!(
                "   {:<10} [{:<15}] {:<22} | {} | {}",
                format!("{}/{}", sock.port, sock.proto).blue(),
                sock.ip.dimmed(),
                proc_label,
                "CLIENTE / DESKTOP EFÊMERO".blue(),
                "Uso de aplicação local".dimmed()
            );
        } else {
            alerts_count += 1;
            println!(
                "   {:<10} [{:<15}] {:<22} | {} | {}",
                format!("{}/{}", sock.port, sock.proto).red().bold(),
                sock.ip.yellow().bold(),
                proc_label,
                "PORTA ÓRFÃ NÃO CATALOGADA".red().bold(),
                "Cadastrar em mnemocine/network/ports.md".yellow()
            );
        }
    }

    // Listar portas catalogadas que estão em repouso (offline)
    for entry in &catalog {
        if entry.host == "psicopompo" && !active_ports_found.contains_key(&entry.port) {
            println!(
                "   {:<10} [{:<15}] {:<22} | {} | {}",
                format!("{}/{}", entry.port, entry.proto).dimmed(),
                entry.bind.dimmed(),
                entry.service.dimmed(),
                "EM REPOUSO / OFFLINE".dimmed(),
                entry.doc_link.dimmed()
            );
        }
    }

    println!();

    // ── 2. Auditoria Remota na Malha Tailscale (Multi-Node Probing) ──────────
    println!(
        "{}",
        "── 🌐 Auditoria de Portas Remotas via Malha Tailscale (WireGuard) ─────".dimmed()
    );

    let remote_nodes = [
        ("kavure", "100.124.146.77", vec![(5432, "PostgreSQL"), (6379, "Valkey"), (9090, "Core API")]),
        ("ybyra", "100.66.224.34", vec![(80, "Nginx HTTP"), (443, "Nginx HTTPS")]),
        ("ybytu", "100.115.253.109", vec![(53, "AdGuard DNS"), (3000, "AdGuard Web"), (3002, "Uptime Kuma")]),
        ("kuaray", "100.94.209.99", vec![(8123, "Home Assistant")]),
    ];

    for (node_name, ip, targets) in remote_nodes {
        println!("   [{}] {} ({})", "NÓ".cyan().bold(), node_name.bold(), ip.dimmed());
        for (port, svc_name) in targets {
            let addr = format!("{}:{}", ip, port);
            let t0 = std::time::Instant::now();
            let status = match timeout(Duration::from_millis(400), TcpStream::connect(&addr)).await {
                Ok(Ok(_stream)) => {
                    let lat = t0.elapsed();
                    format!("{} ({:.1}ms)", "ABERTA / ONLINE".green().bold(), lat.as_secs_f64() * 1000.0)
                }
                Ok(Err(_e)) => "FECHADA / REPOUSO".dimmed().to_string(),
                Err(_) => "TIMEOUT / BLOQUEADA".yellow().dimmed().to_string(),
            };

            println!(
                "      {:<10} {:<24} - {}",
                format!(":{}", port).white().bold(),
                svc_name.dimmed(),
                status
            );
        }
    }

    println!();
    println!(
        "{}",
        "──────────────────────────────────────────────────────────────────────────────"
            .dimmed()
    );

    if alerts_count == 0 {
        println!(
            "{}",
            "✨ Superfície de ataque 100% mapeada e conforme ao catálogo de portas."
                .green()
                .bold()
        );
    } else {
        println!(
            "⚠️  Foram detectadas {} anomalia(s) ou portas não catalogadas. Revise a tabela acima.",
            alerts_count.to_string().yellow().bold()
        );
    }
    println!();

    Ok(())
}
