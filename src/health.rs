use anyhow::Result;
use colored::*;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

pub fn run_system_health() -> Result<()> {
    crate::baseline::print_banner("StênioKernel — Raio-X de Infraestrutura & Saúde dos Serviços (--health)");

    // 1. Armazenamento em Disco
    println!(
        "{}",
        "── 💾 Armazenamento em Disco ──────────────────────────────────────────".dimmed()
    );
    check_disk_health("/", "Raiz do Sistema");
    check_disk_health("/mnt/NVME_PCI", "NVMe PCI (Workspace & Caches)");
    println!();

    // 2. Memória RAM & Swap
    println!(
        "{}",
        "── 🧠 Memória Física & Recursos do Host ───────────────────────────────".dimmed()
    );
    check_memory_health();
    println!();

    // 3. GPU & Aceleração Blackwell
    println!(
        "{}",
        "── ⚡ Aceleração Gráfica & VRAM ───────────────────────────────────────".dimmed()
    );
    check_gpu_health();
    println!();

    // 4. Serviços & Conectividade Local
    println!(
        "{}",
        "── 🔌 Serviços do Hub & Portas de Rede ────────────────────────────────".dimmed()
    );
    check_tcp_service("PostgreSQL", "127.0.0.1", 5432, "Banco Relacional SQLx");
    check_tcp_service(
        "Valkey / Redis",
        "127.0.0.1",
        6379,
        "Barramento de Eventos & Cache",
    );
    check_http_service(
        "stenio-server",
        "http://127.0.0.1:9090",
        "Servidor Rust Axum + Whisper",
    );
    println!();

    // 5. Cadeia Canônica de Backups do Homelab (/mnt/BACKUP)
    println!(
        "{}",
        "── 🛡️ Cadeia de Backups & Integridade do NAS (/mnt/BACKUP) ────────────".dimmed()
    );
    check_backup_chain();
    println!();

    // 6. Malha Tailscale & Heterogeneidade de Sistemas Operacionais
    println!(
        "{}",
        "── 🌐 Malha Tailscale & Sistemas Operacionais (Mnemocine Homelab) ──────".dimmed()
    );
    if let Ok(rt) = tokio::runtime::Runtime::new() {
        let results = rt.block_on(crate::mesh::audit_tailscale_mesh());
        let mut online_count = 0;
        for res in &results {
            let status_badge = if res.is_online {
                online_count += 1;
                let lat_str = match res.latency {
                    Some(l) => format!("{:.1}ms", l.as_secs_f64() * 1000.0),
                    None => "TS-OK".to_string(),
                };
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
            "   Status da Malha: {} de {} nós ativos e conectados.",
            online_count,
            results.len()
        );
    }
    println!();

    // 7. Infraestrutura Docker & Higiene de Imagens
    println!(
        "{}",
        "── 🐳 Infraestrutura Docker & Higiene de Imagens ──────────────────────".dimmed()
    );
    check_docker_health();
    println!();

    println!(
        "{}",
        "✨ Diagnóstico concluído. Infraestrutura pronta para operação."
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
            "Não montado ou inacessível".red().bold()
        );
        return;
    }

    let targets = [
        ("configs-homelab", "Espelho Git + Configs de Todos os Nós"),
        (
            "zomboid-server-kavure",
            "Dados de Jogo / Saves / Configs (Kavure)",
        ),
        ("sumaenima-server-kavure", "Borg Backups / Sumænimá Hub DB"),
        (
            "agentic-ai-server-psicopompo",
            "Cópia Noturna do Vault Obsidian",
        ),
        (
            "monitoring-server-kavure",
            "Métricas Prometheus & Dashboards Grafana",
        ),
    ];

    for (folder, desc) in targets {
        let p = backup_dir.join(folder);
        if p.exists() {
            let mod_time = fs::metadata(&p).and_then(|m| m.modified()).ok();
            let age_str = if let Some(m) = mod_time {
                let elapsed_secs = m.elapsed().map(|d| d.as_secs()).unwrap_or(0);
                let hours = elapsed_secs / 3600;
                if hours < 24 {
                    format!("Íntegro (atualizado há {}h)", hours).green().bold()
                } else {
                    format!("Atenção (>{}h sem update)", hours).yellow().bold()
                }
            } else {
                "Presente".green().bold()
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
                "AUSENTE".red().bold(),
                desc.dimmed()
            );
        }
    }
}

fn check_disk_health(path: &str, label: &str) {
    // Exceção documentada: statvfs nativo requer dep nix (não incluso). Pendente ADR-xxx.
    let output = Command::new("df")
        .args(["-Pk", path])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let total_kb: f64 = parts[1].parse().unwrap_or(0.0);
                    let avail_kb: f64 = parts[3].parse().unwrap_or(0.0);
                    let pct_str = parts[4].trim_end_matches('%');
                    let pct: f64 = pct_str.parse().unwrap_or(0.0);

                    let total_gb = total_kb / (1024.0 * 1024.0);
                    let free_gb = avail_kb / (1024.0 * 1024.0);

                    let status = if pct > 90.0 {
                        format!("CRÍTICO ({}% usado)", pct).red().bold()
                    } else if pct > 75.0 {
                        format!("ALERTA ({}% usado)", pct).yellow().bold()
                    } else {
                        format!("SAUDÁVEL ({}% usado)", pct).green().bold()
                    };

                    println!(
                        "   {:<30} [{}] - {:.1} GB livres de {:.1} GB ({})",
                        label.bold(),
                        path.cyan(),
                        free_gb,
                        total_gb,
                        status
                    );
                    return;
                }
            }
        }
    }
    println!(
        "   {:<30} [{}] - {}",
        label.bold(),
        path.cyan(),
        "Não foi possível inspecionar".yellow()
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
                format!("{:.1}% em uso", used_pct).red().bold()
            } else {
                format!("{:.1}% em uso", used_pct).green().bold()
            };

            println!(
                "   {:<30} {:.1} GB disponíveis de {:.1} GB ({})",
                "Memória RAM Total".bold(),
                avail_gb,
                total_gb,
                status
            );
            return;
        }
    }
    println!(
        "   {:<30} {}",
        "Memória RAM".bold(),
        "Não disponível".yellow()
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
                let parts: Vec<&str> = first_line.split(',').map(|s| s.trim()).collect();
                if parts.len() >= 4 {
                    let name = parts[0];
                    let driver = parts[1];
                    let total = parts[2];
                    let free = parts[3];
                    println!(
                        "   {:<30} {} (Driver {}) | VRAM: {} MiB livres / {} MiB total",
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
        "GPU Física".bold(),
        "Não detectada ou sem driver NVIDIA ativo".yellow()
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
            "OFFLINE (em repouso)".dimmed()
        );
    }
}

pub fn http_get_health(url: &str) -> Option<(bool, u128)> {
    let t0 = Instant::now();
    let health_url = format!("{}/v1/health", url);
    let output = Command::new("xh")
        .args(["-b", "--timeout=1", &health_url])
        .output()
        .ok()?;

    let elapsed = t0.elapsed().as_millis();
    if output.status.success() {
        let s = String::from_utf8_lossy(&output.stdout);
        Some((s.contains("\"status\"") && s.contains("\"ok\""), elapsed))
    } else {
        None
    }
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
        "OFFLINE (em repouso)".dimmed()
    );
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
                "Inativo ou não instalado".dimmed()
            );
            return;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut total_reclaimable = 0u64;

    for line in stdout.lines() {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            let row_type = val.get("Type").and_then(|v| v.as_str()).unwrap_or("");
            let total = val.get("TotalCount").and_then(|v| v.as_str()).unwrap_or("0");
            let active = val.get("Active").and_then(|v| v.as_str()).unwrap_or("0");
            let size = val.get("Size").and_then(|v| v.as_str()).unwrap_or("0B");
            let reclaimable = val.get("Reclaimable").and_then(|v| v.as_str()).unwrap_or("0B");

            let rec_bytes = crate::clean::parse_docker_size(reclaimable);
            total_reclaimable += rec_bytes;

            let badge = if rec_bytes > 1024 * 1024 * 1024 {
                format!("{} ({})", size.bold(), reclaimable.yellow().bold())
            } else {
                format!("{} ({})", size.bold(), reclaimable.dimmed())
            };

            println!(
                "   {:<25} [{:>2} ativos / {:>2} total] - {}",
                format!("Docker {}", row_type).bold(),
                active.green().bold(),
                total.white(),
                badge
            );
        }
    }

    if total_reclaimable > 1024 * 1024 * 1024 {
        println!(
            "   ⚠️  {} acumulado em imagens órfãs/cache. Dica: use '{}' para limpar.",
            crate::clean::format_bytes(total_reclaimable).yellow().bold(),
            "stenio --clean docker".cyan().bold()
        );
    } else {
        println!(
            "   ✨ Docker higienizado e enxuto ({:.2} MiB recuperável).",
            total_reclaimable as f64 / (1024.0 * 1024.0)
        );
    }
}

