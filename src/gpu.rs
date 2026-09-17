use std::fs;
use std::path::Path;
use std::process::Command;

#[allow(dead_code)]
pub struct GpuAuditResult {
    pub whisper_ggml_ok: bool,
    pub bloatware_free: bool,
    pub daemon_online: bool,
    pub hardware_info: Option<String>,
    pub errors: Vec<String>,
    pub messages: Vec<String>,
}

pub fn audit_gpu_subsystem() -> GpuAuditResult {
    let mut messages = Vec::new();
    let mut errors = Vec::new();
    let cache_dir = Path::new("/mnt/NVME_PCI/sumaenimahub/llm_model_cache");

    // 1. Hardware & Driver Query direta via host nvidia-smi (<5ms)
    let hardware_info = query_host_gpu();
    if let Some(ref hw) = hardware_info {
        messages.push(format!("✅ GPU detectada: {}", hw));
    } else {
        messages.push(
            "ℹ️ GPU física não detectada ou ambiente em container sem passthrough".to_string(),
        );
    }

    // 2. Integridade do modelo GGML Q8_0 do stenio-server
    let whisper_model = cache_dir.join("whisper-ggml/ggml-large-v3-turbo-q8_0.bin");
    let whisper_ggml_ok = if whisper_model.is_file() {
        if let Ok(meta) = fs::metadata(&whisper_model) {
            if meta.len() > 800_000_000 {
                let mb = meta.len() / (1024 * 1024);
                messages.push(format!(
                    "✅ Modelo Whisper GGML Q8_0 íntegro no NVMe ({} MB)",
                    mb
                ));
                true
            } else {
                let err = "❌ Modelo Whisper GGML Q8_0 corrompido ou incompleto".to_string();
                messages.push(err.clone());
                errors.push(err);
                false
            }
        } else {
            false
        }
    } else if cache_dir.is_dir() {
        let err = "❌ Modelo Whisper GGML Q8_0 ausente no cache NVMe (/mnt/NVME_PCI/sumaenimahub/llm_model_cache/whisper-ggml/)".to_string();
        messages.push(err.clone());
        errors.push(err);
        false
    } else {
        messages.push("ℹ️ Host sem cache NVMe montado (modo CI / container)".to_string());
        true
    };

    // 3. Garantia de Ausência de Bloatware Legado (SAM2, PaddleX, CT2)
    let mut bloatware_free = true;
    for dead_model in &[
        "sam2",
        "paddlex",
        "gemma-3-1b-it-ct2",
        "whisper-large-v3-turbo-ct2",
    ] {
        let p = cache_dir.join(dead_model);
        if p.exists() {
            bloatware_free = false;
            let err = format!(
                "❌ Regressão de bloatware: modelo legado '{}' detectado em disco!",
                dead_model
            );
            messages.push(err.clone());
            errors.push(err);
        }
    }
    if bloatware_free {
        messages.push("✅ Cache limpo de pesos legados (Zero bloatware)".to_string());
    }

    // 4. Health check do servidor Rust stenio-server (porta 9090)
    let server_url = std::env::var("STENIO_SERVER_URL")
        .or_else(|_| std::env::var("WHISPERD_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let daemon_online = check_daemon_health(&server_url);
    let port_str = server_url.rsplit(':').next().unwrap_or("9090");
    if daemon_online {
        messages.push(format!(
            "✅ Servidor Rust stenio-server ativo e respondendo na porta {}",
            port_str
        ));
    } else {
        messages.push(format!(
            "ℹ️ Servidor Rust stenio-server em repouso (offline no momento em {})",
            server_url
        ));
    }

    GpuAuditResult {
        whisper_ggml_ok,
        bloatware_free,
        daemon_online,
        hardware_info,
        errors,
        messages,
    }
}

fn query_host_gpu() -> Option<String> {
    let output = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,driver_version,memory.total,memory.free",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let first_line = stdout.lines().next()?.trim();
        let parts: Vec<&str> = first_line.split(',').map(|s| s.trim()).collect();
        if parts.len() >= 4 {
            let name = parts[0];
            let driver = parts[1];
            let total_mb = parts[2];
            let free_mb = parts[3];
            return Some(format!(
                "{} (Driver {}) | VRAM: {} MiB livres / {} MiB total",
                name, driver, free_mb, total_mb
            ));
        }
        return Some(first_line.to_string());
    }
    None
}

fn check_daemon_health(url: &str) -> bool {
    let health_url = format!("{}/v1/health", url);
    // Usa xh (alternativa Rust ao curl) conforme AGENTS.md.
    let output = Command::new("xh") // stenio-ignore: ARCH-RUST-CMD-LEGACY
        .args(["--timeout=1", "--quiet", &health_url])
        .output()
        .or_else(|_| {
            Command::new("curl")
                .args(["-s", "-m", "1", &health_url])
                .output()
        }); // stenio-ignore: ARCH-RUST-CMD-LEGACY
    if let Ok(out) = output {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            return s.contains("\"status\":\"ok\"");
        }
    }
    false
}
