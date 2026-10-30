use bollard::query_parameters::ListContainersOptions;
use bollard::Docker;
use colored::*;
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
pub struct DockerViolation {
    pub rule: &'static str,
    pub container: String,
    pub message: String,
    pub severity: DockerSeverity,
}

#[derive(Debug, Clone, Default)]
pub struct DockerAuditReport {
    pub total_containers: usize,
    pub running_containers: usize,
    pub stopped_containers: usize,
    pub violations: Vec<DockerViolation>,
    pub execution_time_ms: f64,
}

/// Connects directly to the Docker socket and inspects live containers and security drift.
pub async fn audit_docker_live() -> Result<DockerAuditReport, String> {
    let start = Instant::now();
    let docker = Docker::connect_with_defaults()
        .map_err(|e| format!("Failed to connect to Docker socket (/var/run/docker.sock): {}", e))?;

    let mut filters = HashMap::new();
    filters.insert("status".to_string(), vec!["running".to_string(), "exited".to_string(), "dead".to_string()]);

    let options = Some(ListContainersOptions {
        all: true,
        filters: Some(filters),
        ..Default::default()
    });

    let containers = docker
        .list_containers(options)
        .await
        .map_err(|e| format!("Failed to list Docker containers: {}", e))?;

    let mut violations = Vec::new();
    let mut running_count = 0;
    let mut stopped_count = 0;

    for c in &containers {
        let name = c
            .names
            .as_ref()
            .and_then(|names| names.first())
            .map(|s| s.trim_start_matches('/'))
            .unwrap_or("unnamed");

        let state_str = c.state.as_ref().map(|s| format!("{:?}", s).to_lowercase()).unwrap_or_default();
        let status = c.status.as_deref().unwrap_or("");

        if state_str.contains("running") {
            running_count += 1;
        } else {
            stopped_count += 1;
            // Check if exited abnormally
            if status.contains("Exited (1")
                || status.contains("Exited (2")
                || status.contains("Exited (137")
                || status.contains("Dead")
            {
                violations.push(DockerViolation {
                    rule: "DOCKER-CONTAINER-FAILED",
                    container: name.to_string(),
                    message: format!("Container is stopped with error status: '{}'", status),
                    severity: DockerSeverity::Error,
                });
            }
        }

        // Check Port Binds: Alert on 0.0.0.0 (wildcard bind vs Tailscale/127.0.0.1)
        if let Some(ports) = &c.ports {
            for p in ports {
                if let Some(ip) = &p.ip {
                    if ip == "0.0.0.0" {
                        let pub_port = p.public_port.unwrap_or(0);
                        let priv_port = p.private_port;
                        violations.push(DockerViolation {
                            rule: "DOCKER-WILDCARD-BIND",
                            container: name.to_string(),
                            message: format!(
                                "Exposes port {}:{} on wildcard 0.0.0.0. Restrict to loopback (127.0.0.1) or Tailscale IP.",
                                pub_port, priv_port
                            ),
                            severity: DockerSeverity::Warning,
                        });
                    }
                }
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    Ok(DockerAuditReport {
        total_containers: containers.len(),
        running_containers: running_count,
        stopped_containers: stopped_count,
        violations,
        execution_time_ms: elapsed,
    })
}

/// Formats and displays the Docker Live Sentinel audit report.
pub fn print_docker_report(report: &DockerAuditReport) {
    println!("\n{}", "══════════════════════════════════════════════════════════════════════════════".bold());
    println!(
        "{} [{:.2}ms]",
        "StenioSentinel Docker Live Inspector (bollard) — Fleet Drift & Ports".bold().cyan(),
        report.execution_time_ms
    );
    println!("{}", "══════════════════════════════════════════════════════════════════════════════".bold());

    let errors_count = report.violations.iter().filter(|v| v.severity == DockerSeverity::Error).count();
    let warnings_count = report.violations.iter().filter(|v| v.severity == DockerSeverity::Warning).count();

    println!("   🐳 Total Containers   : {}", report.total_containers.to_string().bold());
    println!("   🟢 Running Containers : {}", report.running_containers.to_string().green().bold());
    println!("   ⚪ Stopped / Idle     : {}", report.stopped_containers.to_string().bold());
    println!("   ❌ Errors (Failed)    : {}", errors_count.to_string().red().bold());
    println!("   ⚠️  Security Warnings  : {}", warnings_count.to_string().yellow().bold());

    if !report.violations.is_empty() {
        println!("\n{}", "── Observed Container Anomalies ──────────────────────────────────────────────".bold());
        for v in &report.violations {
            match v.severity {
                DockerSeverity::Error => {
                    println!("   {} [{}] in {}:", "❌ ERROR".red().bold(), v.rule.bold(), v.container.cyan());
                    println!("      {}", v.message);
                }
                DockerSeverity::Warning => {
                    println!("   {}  [{}] in {}:", "⚠️  WARN".yellow().bold(), v.rule.bold(), v.container.cyan());
                    println!("      {}", v.message);
                }
            }
        }
    } else {
        println!("\n   ✨ {}", "All containers are healthy, with zero unexpected failures or insecure binds!".green().bold());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_violation_structure() {
        let violation = DockerViolation {
            rule: "DOCKER-WILDCARD-BIND",
            container: "web-app".to_string(),
            message: "Port 80 exposed on 0.0.0.0".to_string(),
            severity: DockerSeverity::Warning,
        };

        assert_eq!(violation.rule, "DOCKER-WILDCARD-BIND");
        assert_eq!(violation.severity, DockerSeverity::Warning);
    }
}
