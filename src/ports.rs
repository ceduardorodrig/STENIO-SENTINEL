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
    let output = match Command::new("ss").args(["-Htlpn"]).output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ss_output(&stdout)
}

/// Faz o parsing da saída tabular do comando ss (-Htlpn ou -tlpn)
pub fn parse_ss_output(stdout: &str) -> Vec<ActiveSocket> {
    let mut sockets = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("State") || trimmed.starts_with("Netid") {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() >= 4 {
            // No ss -Htlpn ou -tlpn com State Recv-Q Send-Q Local Address:Port Peer Address:Port
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

/// Executa a auditoria completa do Porteiro das Portas (Attack Surface Management)
pub async fn run_ports_audit(root: &Path) -> Result<()> {
    crate::baseline::print_banner(
        "StênioKernel — Porteiro das Portas & Superfície de Ataque (--ports)",
    );

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

        let proc_label = sock.process.as_deref().unwrap_or("sistema / docker").cyan();

        let entries_for_port = catalog_map.get(&sock.port);
        let psicopompo_entry =
            entries_for_port.and_then(|v| v.iter().find(|e| e.host == "psicopompo"));

        if let Some(entry) = psicopompo_entry {
            // Verificar se o bind é seguro
            let is_wide_open = sock.ip == "0.0.0.0" || sock.ip == "::";
            let should_be_restricted = entry.bind.contains("127.0.0.1")
                || entry.bind.contains("tailscale0")
                || entry.bind.contains("100.");
            let is_lan_authorized = entry.bind.contains("LAN")
                || entry.bind.contains("Swarm Ingress")
                || entry.port == 7946;

            if is_wide_open && should_be_restricted && !is_lan_authorized {
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
        } else if sock.port > 30000 || sock.port == 1716 || sock.port == 27036 || sock.port == 9863
        {
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

    // ── 2. Auditoria Remota na Malha Tailscale & SSH Deep Inspection ──────────
    println!(
        "{}",
        "── 🌐 Auditoria Remota dos Nós Homelab via Tailscale & SSH ─────────────".dimmed()
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
            "NÓ".cyan().bold(),
            node_name.bold(),
            ip.dimmed()
        );

        // 1. Tentar SSH para raio-X completo interno com detecção de re-auth Tailscale
        let outcome =
            crate::remote::run_ssh(node_name, "sudo -n ss -Htlpn 2>/dev/null || ss -Htlpn", 4);

        let mut ssh_success = false;

        match outcome {
            crate::remote::RemoteOutcome::Success(ref stdout_str) if !stdout_str.is_empty() => {
                let sockets = parse_ss_output(stdout_str);

                if !sockets.is_empty() {
                    ssh_success = true;
                    let mut node_active_ports = HashMap::new();

                    for sock in sockets {
                        if node_active_ports.contains_key(&sock.port) {
                            continue;
                        }
                        node_active_ports.insert(sock.port, sock.clone());

                        let proc_label =
                            sock.process.as_deref().unwrap_or("sistema / docker").cyan();

                        let entries_for_port = catalog_map.get(&sock.port);
                        let node_entry =
                            entries_for_port.and_then(|v| v.iter().find(|e| e.host == node_name));

                        if let Some(entry) = node_entry {
                            let is_wide_open = sock.ip == "0.0.0.0" || sock.ip == "::";
                            let is_wan_allowed = (node_name == "ybyra"
                                && (sock.port == 80 || sock.port == 443))
                                || entry.bind.contains("LAN")
                                || entry.bind.contains("Swarm Ingress")
                                || sock.port == 7946;

                            if is_wide_open && !is_wan_allowed {
                                alerts_count += 1;
                                println!(
                                    "      {:<10} [{:<15}] {:<22} | {} | {}",
                                    format!("{}/{}", sock.port, sock.proto).yellow().bold(),
                                    sock.ip.red().bold(),
                                    entry.service.white().bold(),
                                    "⚠️ BIND 0.0.0.0 NÃO AUTORIZADO".red().bold(),
                                    entry.doc_link.dimmed()
                                );
                            } else {
                                println!(
                                    "      {:<10} [{:<15}] {:<22} | {} | {}",
                                    format!("{}/{}", sock.port, sock.proto).green().bold(),
                                    sock.ip.dimmed(),
                                    entry.service.white().bold(),
                                    "CONFORME".green().bold(),
                                    entry.doc_link.dimmed()
                                );
                            }
                        } else if sock.ip.starts_with("127.0.0.") || sock.ip == "::1" {
                            println!(
                                "      {:<10} [{:<15}] {:<22} | {} | {}",
                                format!("{}/{}", sock.port, sock.proto).dimmed(),
                                sock.ip.dimmed(),
                                proc_label,
                                "LOCALHOST / DEV TEMPORÁRIO".dimmed(),
                                "Não exposto à rede externa".dimmed()
                            );
                        } else if sock.port > 30000 || sock.port == 22 {
                            println!(
                                "      {:<10} [{:<15}] {:<22} | {} | {}",
                                format!("{}/{}", sock.port, sock.proto).blue(),
                                sock.ip.dimmed(),
                                proc_label,
                                if sock.port == 22 {
                                    "SSH DAEMON".blue()
                                } else {
                                    "CLIENTE / DESKTOP EFÊMERO".blue()
                                },
                                "Acesso de gestão / aplicação".dimmed()
                            );
                        } else {
                            alerts_count += 1;
                            println!(
                                "      {:<10} [{:<15}] {:<22} | {} | {}",
                                format!("{}/{}", sock.port, sock.proto).red().bold(),
                                sock.ip.yellow().bold(),
                                proc_label,
                                "PORTA ÓRFÃ NÃO CATALOGADA".red().bold(),
                                "Cadastrar em mnemocine/network/ports.md".yellow()
                            );
                        }
                    }

                    // Reportar portas catalogadas em repouso no nó remoto
                    for entry in &catalog {
                        if entry.host == node_name && !node_active_ports.contains_key(&entry.port) {
                            println!(
                                "      {:<10} [{:<15}] {:<22} | {} | {}",
                                format!("{}/{}", entry.port, entry.proto).dimmed(),
                                entry.bind.dimmed(),
                                entry.service.dimmed(),
                                "EM REPOUSO / OFFLINE".dimmed(),
                                entry.doc_link.dimmed()
                            );
                        }
                    }
                }
            }
            crate::remote::RemoteOutcome::AuthRequired { ref auth_url, .. } => {
                println!(
                    "      ⚠️  {} {}",
                    "AUTENTICAÇÃO TAILSCALE SSH NECESSÁRIA:".yellow().bold(),
                    auth_url.cyan().underline().bold()
                );
                println!(
                    "         {}",
                    "👉 Abra o link acima no navegador para autorizar o acesso SSH a este nó."
                        .dimmed()
                );
            }
            _ => {}
        }

        // 2. Se o SSH não respondeu ou falhou, fallback transparente para TCP Probing
        if !ssh_success {
            println!(
                "      {}",
                "ℹ️  SSH indisponível ou pendente — executando TCP Probing direto via Tailnet..."
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
                                "ABERTA / ONLINE".green().bold(),
                                lat.as_secs_f64() * 1000.0
                            )
                        }
                        Ok(Err(_e)) => "FECHADA / REPOUSO".dimmed().to_string(),
                        Err(_) => "TIMEOUT / BLOQUEADA".yellow().dimmed().to_string(),
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
