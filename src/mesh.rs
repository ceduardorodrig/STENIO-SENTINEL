use colored::*;
use serde::Deserialize;
use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct DynamicNode {
    pub name: String,
    pub ip: String,
    pub role: String,
    pub is_server: bool,
    pub port: u16,
    pub os: String,
    pub shell: String,
}

impl DynamicNode {
    pub fn from_tailscale(name: String, ip: String, raw_os: &str) -> Self {
        let (role, is_server, os, shell) = resolve_node_role(&name, raw_os);
        Self {
            name,
            ip,
            role,
            is_server,
            port: 22,
            os,
            shell,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NodeStatus {
    pub node: DynamicNode,
    pub is_online: bool,
    pub latency: Option<Duration>,
    pub tailscale_online: bool,
    pub error_msg: Option<String>,
}

impl NodeStatus {
    pub fn ts_active(node: DynamicNode, tailscale_online: bool, msg: &str) -> Self {
        Self {
            node,
            is_online: true,
            latency: None,
            tailscale_online,
            error_msg: Some(msg.to_string()),
        }
    }

    pub fn offline(node: DynamicNode, tailscale_online: bool, error: impl Into<String>) -> Self {
        Self {
            node,
            is_online: false,
            latency: None,
            tailscale_online,
            error_msg: Some(error.into()),
        }
    }
}

#[derive(Deserialize)]
struct TailscaleSelf {
    #[serde(rename = "HostName")]
    host_name: Option<String>,
    #[serde(rename = "TailscaleIPs")]
    tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "OS")]
    os: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct TailscalePeer {
    #[serde(rename = "HostName")]
    host_name: Option<String>,
    #[serde(rename = "Online")]
    online: Option<bool>,
    #[serde(rename = "Active")]
    active: Option<bool>,
    #[serde(rename = "TailscaleIPs")]
    tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "OS")]
    os: Option<String>,
}

#[derive(Deserialize)]
struct TailscaleStatus {
    #[serde(rename = "Self")]
    self_node: Option<TailscaleSelf>,
    #[serde(rename = "Peer")]
    peers: Option<HashMap<String, TailscalePeer>>,
}

/// Mapeia o papel canônico do nó e shell padrão a partir do seu hostname e OS
fn resolve_node_role(name: &str, os: &str) -> (String, bool, String, String) {
    let lower = name.to_lowercase();
    if lower.contains("psicopompo") {
        (
            "Dev + GPU Workers (RTX 5050) / NAS (NFSv4)".to_string(),
            true,
            "CachyOS (Arch)".to_string(),
            "fish".to_string(),
        )
    } else if lower.contains("ybyra") {
        (
            "Cloud Borda Primária / Nginx Reverse Proxy / SPA".to_string(),
            true,
            "Ubuntu 24.04".to_string(),
            "bash".to_string(),
        )
    } else if lower.contains("kuaray") {
        (
            "Multimídia / Home Assistant / Media Server".to_string(),
            true,
            "Linux Mint 22.3".to_string(),
            "bash".to_string(),
        )
    } else if lower.contains("ybytu") {
        (
            "Cloud Exit Node / DNS Primário (AdGuard)".to_string(),
            true,
            "Ubuntu 24.04".to_string(),
            "bash".to_string(),
        )
    } else if lower.contains("kavure") {
        (
            "Serviços Dedicados / Zomboid / Sumænimá Docker".to_string(),
            true,
            "Ubuntu 24.04".to_string(),
            "bash".to_string(),
        )
    } else if lower.contains("miracena") {
        (
            "Estação de Trabalho / Workspace".to_string(),
            false,
            "Linux".to_string(),
            "bash".to_string(),
        )
    } else if lower.contains("anansi") {
        (
            "Dispositivo Móvel (Android)".to_string(),
            false,
            "Android".to_string(),
            "sh".to_string(),
        )
    } else {
        let detected_os = if os.is_empty() {
            "Linux".to_string()
        } else {
            os.to_string()
        };
        (
            "Nó da Tailnet Mnemocine".to_string(),
            false,
            detected_os,
            "bash".to_string(),
        )
    }
}

/// Descobre dinamicamente TODOS os nós da Tailnet conectada.
/// É impossível esquecer um nó: qualquer máquina adicionada na malha é detectada automaticamente.
pub fn discover_tailscale_nodes() -> Vec<(DynamicNode, bool)> {
    let mut nodes = Vec::new();

    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            if let Ok(status) = serde_json::from_slice::<TailscaleStatus>(&out.stdout) {
                // 1. Adiciona o nó local (Self)
                if let Some(self_node) = status.self_node {
                    let name = self_node
                        .host_name
                        .unwrap_or_else(|| "localhost".to_string());
                    let ip = self_node
                        .tailscale_ips
                        .and_then(|ips| ips.into_iter().find(|i| !i.contains(':')))
                        .unwrap_or_else(|| "100.82.51.112".to_string());
                    let raw_os = self_node.os.unwrap_or_else(|| "linux".to_string());
                    let node = DynamicNode::from_tailscale(name, ip, &raw_os);
                    nodes.push((node, true)); // Local sempre online
                }

                // 2. Adiciona todos os peers da Tailnet dinamicamente
                if let Some(peers) = status.peers {
                    for (_, peer) in peers {
                        let name = match peer.host_name {
                            Some(n) => n,
                            None => continue,
                        };
                        let ip = match peer
                            .tailscale_ips
                            .and_then(|ips| ips.into_iter().find(|i| !i.contains(':')))
                        {
                            Some(ip) => ip,
                            None => continue,
                        };
                        let raw_os = peer.os.unwrap_or_else(|| "linux".to_string());
                        let is_online = peer.online.unwrap_or(false);
                        let node = DynamicNode::from_tailscale(name, ip, &raw_os);
                        nodes.push((node, is_online));
                    }
                }
            }
        }
    }

    // Fallback de segurança se tailscale CLI não estiver no PATH
    if nodes.is_empty() {
        let fallbacks = [
            (
                "psicopompo",
                "100.82.51.112",
                "Dev + GPU Workers (RTX 5050) / NAS (NFSv4)",
                true,
                "CachyOS",
                "fish",
            ),
            (
                "ybyra",
                "100.66.224.34",
                "Cloud Borda Primária / Nginx Reverse Proxy / SPA",
                true,
                "Ubuntu 24.04",
                "bash",
            ),
            (
                "kuaray",
                "100.94.209.99",
                "Multimídia / Home Assistant / Media Server",
                true,
                "Linux Mint 22.3",
                "bash",
            ),
            (
                "ybytu",
                "100.115.253.109",
                "Cloud Exit Node / DNS Primário (AdGuard)",
                true,
                "Ubuntu 24.04",
                "bash",
            ),
            (
                "kavure",
                "100.124.146.77",
                "Serviços Dedicados / Zomboid / Sumænimá Docker",
                true,
                "Ubuntu 24.04",
                "bash",
            ),
        ];
        for (name, ip, role, is_server, os, shell) in fallbacks {
            nodes.push((
                DynamicNode {
                    name: name.to_string(),
                    ip: ip.to_string(),
                    role: role.to_string(),
                    is_server,
                    port: 22,
                    os: os.to_string(),
                    shell: shell.to_string(),
                },
                true,
            ));
        }
    }

    // Ordena: Servidores principais primeiro, depois ordem alfabética
    nodes.sort_by(|a, b| {
        b.0.is_server
            .cmp(&a.0.is_server)
            .then_with(|| a.0.name.cmp(&b.0.name))
    });

    nodes
}

/// Dispara teste de reachability TCP em paralelo
async fn probe_node(node: DynamicNode, tailscale_online: bool) -> NodeStatus {
    let start = Instant::now();
    let addr = format!("{}:{}", node.ip, node.port);

    // Timeout de 1500ms para acomodar links remotos de nuvem frios (como ybytu)
    match timeout(Duration::from_millis(1500), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => {
            let latency = start.elapsed();
            NodeStatus {
                node,
                is_online: true,
                latency: Some(latency),
                tailscale_online,
                error_msg: None,
            }
        }
        Ok(Err(e)) => {
            let latency = start.elapsed();
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                // Host respondeu com TCP RST (está online na rede, apenas porta fechada)
                NodeStatus {
                    node,
                    is_online: true,
                    latency: Some(latency),
                    tailscale_online,
                    error_msg: Some("Porta 22 filtrada (Host ativo)".to_string()),
                }
            } else if tailscale_online {
                // Tailscale daemon confirmou que está online via WireGuard
                NodeStatus::ts_active(node, tailscale_online, "Ativo no Tailscale")
            } else {
                NodeStatus::offline(node, tailscale_online, e.to_string())
            }
        }
        Err(_) => {
            if tailscale_online {
                NodeStatus::ts_active(node, tailscale_online, "Ativo no Tailscale (Porta com timeout)")
            } else {
                NodeStatus::offline(node, tailscale_online, "Timeout (>1500ms)")
            }
        }
    }
}

/// Audita todos os nós descobertos dinamicamente em paralelo usando Tokio
pub async fn audit_tailscale_mesh() -> Vec<NodeStatus> {
    let discovered = discover_tailscale_nodes();

    let mut handles = Vec::new();
    for (node, ts_online) in discovered {
        handles.push(tokio::spawn(
            async move { probe_node(node, ts_online).await },
        ));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(res) = handle.await {
            results.push(res);
        }
    }
    results
}

/// Imprime o relatório visual da malha Homelab no terminal
pub fn print_mesh_report(results: &[NodeStatus], total_duration: Duration) {
    let badge = format!("[{:.2?}]", total_duration);
    crate::baseline::print_banner_with_badge(
        "StenioSentinel — Topologia da Malha Tailscale (Mnemocine Homelab)",
        &badge,
    );

    let mut online_count = 0;
    for res in results {
        let status_badge = if res.is_online {
            online_count += 1;
            let lat_str = match res.latency {
                Some(l) => format!("{:.1}ms", l.as_secs_f64() * 1000.0),
                None => "TS-OK".to_string(),
            };
            format!("● ONLINE [{}]", lat_str).green().bold()
        } else {
            "○ OFFLINE".red().bold()
        };

        let os_shell = format!("{}/{}", res.node.os, res.node.shell);

        println!(
            " {:<15} {:<22} {:<15} {:<16} {}",
            res.node.name.bold(),
            status_badge,
            res.node.ip.dimmed(),
            os_shell.cyan(),
            res.node.role
        );
        if let Some(ref err) = res.error_msg {
            if !res.is_online {
                println!("                  └── Motivo: {}", err.dimmed());
            }
        }
    }

    println!();
    println!(
        "{}",
        format!(
            "✨ Malha Homelab: {} de {} nós ativos e conectados",
            online_count,
            results.len()
        )
        .green()
        .bold()
    );
    println!();
}
