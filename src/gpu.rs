use std::fs;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

/// Canonical remediation target for any GPU work that bypasses the gateway.
const GPU_CENTRALIZATION_GUIDE: &str = "mnemocine/guides/gpu-centralization.md";

/// Default loopback address of the `hl-infer` GPU gateway (`hl-infer.service`).
/// Overridable with the `HL_INFER_URL` environment variable.
const DEFAULT_HL_INFER_URL: &str = "http://127.0.0.1:9095";

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
    let primary_cache = Path::new("/mnt/NVME_PCI/homelab/sumaenimahub/llm_model_cache");
    let fallback_cache = Path::new("/mnt/NVME_PCI/agentic-ai/sumaenimahub/llm_model_cache");
    let cache_dir = if primary_cache.is_dir() {
        primary_cache
    } else {
        fallback_cache
    };

    // 1. Hardware & Driver Query directly via host nvidia-smi (<5ms)
    let hardware_info = query_host_gpu();
    if let Some(ref hw) = hardware_info {
        messages.push(format!("✅ GPU detected: {}", hw));
    } else {
        messages.push(
            "ℹ️ Physical GPU not detected or container environment without passthrough".to_string(),
        );
    }

    // 2. Whisper GGML Q8_0 model integrity for stenio-server
    let whisper_model = cache_dir.join("whisper-ggml/ggml-large-v3-turbo-q8_0.bin");
    let whisper_ggml_ok = if whisper_model.is_file() {
        if let Ok(meta) = fs::metadata(&whisper_model) {
            if meta.len() > 800_000_000 {
                let mb = meta.len() / (1024 * 1024);
                messages.push(format!(
                    "✅ Whisper GGML Q8_0 model intact on NVMe ({} MB)",
                    mb
                ));
                true
            } else {
                let err = "❌ Whisper GGML Q8_0 model corrupted or incomplete".to_string();
                messages.push(err.clone());
                errors.push(err);
                false
            }
        } else {
            false
        }
    } else if cache_dir.is_dir() {
        let err = format!(
            "❌ Whisper GGML Q8_0 model missing in NVMe cache ({}/whisper-ggml/)",
            cache_dir.display()
        );
        messages.push(err.clone());
        errors.push(err);
        false
    } else {
        messages.push("ℹ️ Host without mounted NVMe cache (CI / container mode)".to_string());
        true
    };

    // 3. Assurance of absence of legacy bloatware (SAM2, PaddleX, CT2)
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
                "❌ Bloatware regression: legacy model '{}' detected on disk!",
                dead_model
            );
            messages.push(err.clone());
            errors.push(err);
        }
    }
    if bloatware_free {
        messages.push("✅ Cache clean of legacy weights (Zero bloatware)".to_string());
    }

    // 4. Health check of stenio-server Rust server (port 9090)
    let server_url = std::env::var("STENIO_SERVER_URL")
        .or_else(|_| std::env::var("WHISPERD_URL"))
        .unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let daemon_online = check_daemon_health(&server_url);
    let port_str = server_url.rsplit(':').next().unwrap_or("9090");
    if daemon_online {
        messages.push(format!(
            "✅ Rust server stenio-server active and listening on port {}",
            port_str
        ));
    } else {
        messages.push(format!(
            "ℹ️ Rust server stenio-server at rest (currently offline at {})",
            server_url
        ));
    }

    // 5. GPU gateway (hl-infer) — who holds VRAM, and is any work bypassing it?
    //    Never aborts the audit: an absent gateway is reported as "at rest",
    //    exactly like the daemon probe above.
    let gateway_base = gateway_base_url();
    let gateway = probe_gpu_gateway(&gateway_base);
    let (gateway_messages, gateway_errors) = summarize_gateway(&gateway_base, &gateway);
    messages.extend(gateway_messages);
    errors.extend(gateway_errors);

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
        let parts = crate::util::csv_fields(first_line);
        if parts.len() >= 4 {
            let name = parts[0];
            let driver = parts[1];
            let total_mb = parts[2];
            let free_mb = parts[3];
            return Some(format!(
                "{} (Driver {}) | VRAM: {} MiB free / {} MiB total",
                name, driver, free_mb, total_mb
            ));
        }
        return Some(first_line.to_string());
    }
    None
}

fn check_daemon_health(url: &str) -> bool {
    crate::health::http_get_health(url)
        .map(|(ok, _)| ok)
        .unwrap_or(false)
}

// ── GPU gateway (hl-infer) visibility ───────────────────────────────────────
//
// The gateway is the single arbiter of the scarce RTX 5050 (ADR-020). This
// diagnostic mirrors `hl-infer audit` from the engine side: it reads the live
// consumer classification and flags any process holding VRAM without a lease.
// It is deliberately additive — no rule id, no registry change — and degrades
// to "at rest" when the gateway is absent.
//
// HTTP client choice: the crate has no JSON-capable HTTP dependency, so we reuse
// the exact `xh` (Rust) client already used by `crate::health::http_get_health`
// via the shared `crate::health::http_get_body` helper, and parse with the
// already-present `serde_json`. No new dependency is introduced.

/// One GPU process as classified by the gateway against its granted leases.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct GpuConsumer {
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub used_bytes: u64,
    /// `managed` (matches a lease) · `desktop` (known non-inference user) ·
    /// `unmanaged` (holding VRAM with no lease — drift).
    #[serde(default)]
    pub status: String,
}

/// Payload of `GET /v1/gpu/consumers`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct GpuConsumers {
    #[serde(default)]
    pub unmanaged: u32,
    #[serde(default)]
    pub processes: Vec<GpuConsumer>,
}

/// Payload of `GET /v1/queue` (the nested `vram` object is not needed here).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct GpuQueue {
    #[serde(default)]
    pub pending: u64,
    #[serde(default)]
    pub admitted: u64,
    #[serde(default)]
    pub reserved_bytes: u64,
    #[serde(default)]
    pub effective_free_bytes: u64,
}

/// A GPU process holding VRAM with no lease — work that bypasses the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuDrift {
    pub pid: u32,
    pub name: String,
    pub used_bytes: u64,
}

impl GpuDrift {
    /// VRAM held, in MiB (integer floor, matching `nvidia-smi` reporting).
    pub fn mib(&self) -> u64 {
        self.used_bytes / (1024 * 1024)
    }

    /// Human-readable finding with the canonical remediation pointer.
    pub fn describe(&self) -> String {
        format!(
            "❌ GPU drift: pid {} ('{}') holds {} MiB with no hl-infer lease — GPU work bypassing the centralized gateway. Remediation: {}",
            self.pid,
            self.name,
            self.mib(),
            GPU_CENTRALIZATION_GUIDE
        )
    }
}

/// Live view of the GPU gateway, or a graceful "at rest" marker when absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GpuGatewayReport {
    pub online: bool,
    pub ready: bool,
    pub consumers: Option<GpuConsumers>,
    pub queue: Option<GpuQueue>,
    pub drift: Vec<GpuDrift>,
}

/// Parses `GET /v1/gpu/consumers`; `None` on malformed JSON.
pub fn parse_consumers(json: &str) -> Option<GpuConsumers> {
    serde_json::from_str(json).ok()
}

/// Parses `GET /v1/queue`; `None` on malformed JSON.
pub fn parse_queue(json: &str) -> Option<GpuQueue> {
    serde_json::from_str(json).ok()
}

/// Interprets `GET /v1/ready`. Reaching this with an HTTP 200 body is itself the
/// semantic green light (`503` without a GPU is filtered out upstream by `xh`
/// `--check-status`); an explicit denial in the body downgrades it.
pub fn parse_ready(json: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(value) => {
            if let Some(ready) = value.get("ready").and_then(|v| v.as_bool()) {
                return ready;
            }
            if let Some(status) = value.get("status").and_then(|v| v.as_str()) {
                return !matches!(status, "unavailable" | "not_ready" | "down");
            }
            true
        }
        // A reachable but non-JSON readiness body is treated as ready.
        Err(_) => true,
    }
}

/// Extracts the drift findings (processes holding VRAM without a lease).
pub fn classify_gpu_drift(consumers: &GpuConsumers) -> Vec<GpuDrift> {
    consumers
        .processes
        .iter()
        .filter(|p| p.status.eq_ignore_ascii_case("unmanaged"))
        .map(|p| GpuDrift {
            pid: p.pid,
            name: p.name.clone(),
            used_bytes: p.used_bytes,
        })
        .collect()
}

/// Normalizes a configured base URL (empty/whitespace falls back to the default).
fn normalize_base_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        DEFAULT_HL_INFER_URL.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Resolves the gateway base URL from `HL_INFER_URL` (default loopback).
fn gateway_base_url() -> String {
    normalize_base_url(&std::env::var("HL_INFER_URL").unwrap_or_default())
}

/// GETs `base + path` through the shared `xh` helper.
fn gateway_get(base: &str, path: &str) -> Option<String> {
    crate::health::http_get_body(&format!("{}{}", base, path))
}

/// Probes the GPU gateway. Never fails: an absent/unreachable gateway yields an
/// offline report so the caller reports "at rest" instead of aborting the audit.
pub fn probe_gpu_gateway(base: &str) -> GpuGatewayReport {
    let mut report = GpuGatewayReport::default();

    // Process liveness (`/v1/health`) separates "unreachable" from "up but no
    // GPU ready" (`/v1/ready` answers 503 without a GPU — ADR-020).
    if crate::health::http_get_health(base).is_none() {
        return report;
    }
    report.online = true;

    if let Some(body) = gateway_get(base, "/v1/ready") {
        report.ready = parse_ready(&body);
    }
    if let Some(consumers) =
        gateway_get(base, "/v1/gpu/consumers").and_then(|b| parse_consumers(&b))
    {
        report.drift = classify_gpu_drift(&consumers);
        report.consumers = Some(consumers);
    }
    if let Some(body) = gateway_get(base, "/v1/queue") {
        report.queue = parse_queue(&body);
    }
    report
}

/// Renders a gateway report into audit `messages` and drift `errors`. Pure so
/// the online/offline and drift plumbing is unit-testable without a gateway.
pub fn summarize_gateway(base: &str, report: &GpuGatewayReport) -> (Vec<String>, Vec<String>) {
    let mut messages = Vec::new();
    let mut errors = Vec::new();

    if !report.online {
        messages.push(format!(
            "ℹ️ GPU gateway hl-infer at rest / unreachable at {} (no central arbitration active)",
            base
        ));
        return (messages, errors);
    }

    let readiness = if report.ready {
        "GPU ready"
    } else {
        "reachable, no GPU ready"
    };
    messages.push(format!(
        "✅ GPU gateway hl-infer online at {} ({})",
        base, readiness
    ));

    if let Some(consumers) = &report.consumers {
        messages.push(format!(
            "ℹ️ GPU consumers: {} process(es), {} unmanaged (no lease)",
            consumers.processes.len(),
            consumers.unmanaged
        ));
    }
    if let Some(queue) = &report.queue {
        messages.push(format!(
            "ℹ️ GPU queue: {} pending, {} admitted, {} MiB reserved, {} MiB effective free",
            queue.pending,
            queue.admitted,
            queue.reserved_bytes / (1024 * 1024),
            queue.effective_free_bytes / (1024 * 1024)
        ));
    }
    for drift in &report.drift {
        let finding = drift.describe();
        messages.push(finding.clone());
        errors.push(finding);
    }

    (messages, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONSUMERS_JSON: &str = r#"{
        "unmanaged": 1,
        "leases": [{"id": "job-000001", "status": "admitted"}],
        "processes": [
            {"pid": 111, "name": "steniorec", "used_bytes": 2147483648, "status": "managed"},
            {"pid": 222, "name": "firefox", "used_bytes": 268435456, "status": "desktop"},
            {"pid": 333, "name": "rogue-worker", "used_bytes": 1073741824, "status": "unmanaged"}
        ]
    }"#;

    #[test]
    fn parses_consumers_payload() {
        let consumers = parse_consumers(CONSUMERS_JSON).unwrap();
        assert_eq!(consumers.unmanaged, 1);
        assert_eq!(consumers.processes.len(), 3);
        assert_eq!(consumers.processes[2].name, "rogue-worker");
        assert_eq!(consumers.processes[2].used_bytes, 1_073_741_824);
    }

    #[test]
    fn rejects_malformed_consumers_json() {
        assert!(parse_consumers("not json").is_none());
    }

    #[test]
    fn classifies_only_unmanaged_as_drift() {
        let consumers = parse_consumers(CONSUMERS_JSON).unwrap();
        let drift = classify_gpu_drift(&consumers);
        assert_eq!(drift.len(), 1);
        assert_eq!(drift[0].pid, 333);
        assert_eq!(drift[0].name, "rogue-worker");
        assert_eq!(drift[0].mib(), 1024);
    }

    #[test]
    fn drift_message_carries_remediation_pointer() {
        let consumers = parse_consumers(CONSUMERS_JSON).unwrap();
        let drift = classify_gpu_drift(&consumers);
        let message = drift[0].describe();
        assert!(message.contains("pid 333"));
        assert!(message.contains("1024 MiB"));
        assert!(message.contains(GPU_CENTRALIZATION_GUIDE));
    }

    #[test]
    fn status_matching_is_case_insensitive() {
        let json = r#"{"processes":[{"pid":7,"name":"x","used_bytes":0,"status":"UNMANAGED"}]}"#;
        let consumers = parse_consumers(json).unwrap();
        assert_eq!(classify_gpu_drift(&consumers).len(), 1);
    }

    #[test]
    fn parses_queue_payload() {
        let json = r#"{"pending":2,"admitted":1,"reserved_bytes":1900000000,
            "effective_free_bytes":5000000000,"vram":{"total_bytes":8589934592}}"#;
        let queue = parse_queue(json).unwrap();
        assert_eq!(queue.pending, 2);
        assert_eq!(queue.admitted, 1);
        assert_eq!(queue.reserved_bytes, 1_900_000_000);
        assert_eq!(queue.effective_free_bytes, 5_000_000_000);
    }

    #[test]
    fn parses_ready_variants() {
        assert!(parse_ready(r#"{"ready":true}"#));
        assert!(!parse_ready(r#"{"ready":false}"#));
        assert!(!parse_ready(r#"{"status":"unavailable"}"#));
        assert!(parse_ready(r#"{"status":"ok"}"#));
        assert!(parse_ready("plain body"));
    }

    #[test]
    fn normalizes_gateway_base_url() {
        assert_eq!(
            normalize_base_url("http://127.0.0.1:9095/"),
            "http://127.0.0.1:9095"
        );
        assert_eq!(normalize_base_url("  http://gpu:9095  "), "http://gpu:9095");
        assert_eq!(normalize_base_url(""), DEFAULT_HL_INFER_URL);
        assert_eq!(normalize_base_url("   "), DEFAULT_HL_INFER_URL);
    }

    #[test]
    fn offline_report_defaults_to_at_rest() {
        let report = GpuGatewayReport::default();
        assert!(!report.online);
        assert!(!report.ready);
        assert!(report.consumers.is_none());
        assert!(report.queue.is_none());
        assert!(report.drift.is_empty());
    }

    #[test]
    fn offline_gateway_is_reported_at_rest_without_errors() {
        let report = GpuGatewayReport::default();
        let (messages, errors) = summarize_gateway(DEFAULT_HL_INFER_URL, &report);
        assert_eq!(errors.len(), 0);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("at rest / unreachable"));
    }

    #[test]
    fn unmanaged_consumer_becomes_a_drift_error() {
        let consumers = parse_consumers(CONSUMERS_JSON).unwrap();
        let report = GpuGatewayReport {
            online: true,
            ready: true,
            drift: classify_gpu_drift(&consumers),
            consumers: Some(consumers),
            queue: parse_queue(
                r#"{"pending":1,"admitted":0,"reserved_bytes":0,"effective_free_bytes":100}"#,
            ),
        };
        let (messages, errors) = summarize_gateway(DEFAULT_HL_INFER_URL, &report);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("pid 333"));
        assert!(errors[0].contains(GPU_CENTRALIZATION_GUIDE));
        assert!(messages.iter().any(|m| m.contains("1 unmanaged")));
        assert!(messages.iter().any(|m| m.contains("1 pending")));
    }
}
