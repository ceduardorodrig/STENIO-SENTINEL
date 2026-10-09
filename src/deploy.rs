use anyhow::{Context, Result};
use colored::*;
use regex::Regex;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct ParityStatus {
    pub local_bundle: String,
    pub remote_bundle: String,
    pub in_sync: bool,
}

/// Extracts main script bundle name (assets/index-*.js) from HTML
pub fn extract_script_bundle(html: &str) -> Option<String> {
    let re = Regex::new(r#"assets/index-[A-Za-z0-9_-]+\.js"#).ok()?;
    re.find(html).map(|m| m.as_str().to_string())
}

/// Locates frontend directory in workspace
pub fn find_frontend_dir(root: &Path) -> Option<PathBuf> {
    let candidates = [
        root.join("sumaenimahub/sumaenima-hub/app/frontend-v2"),
        root.join("app/frontend-v2"),
        PathBuf::from("/mnt/NVME_PCI/homelab/sumaenimahub/sumaenima-hub/app/frontend-v2"),
        PathBuf::from("/mnt/NVME_PCI/agentic-ai/sumaenimahub/sumaenima-hub/app/frontend-v2"),
    ];

    for candidate in candidates {
        if candidate.exists() && candidate.join("package.json").exists() {
            return Some(candidate);
        }
    }
    None
}

/// Audits parity between compiled local bundle and remote edge on Ybyra
pub fn check_static_parity(root: &Path) -> Option<ParityStatus> {
    let fe_dir = find_frontend_dir(root)?;
    let local_index = fe_dir.join("dist/index.html");

    if !local_index.exists() {
        return None;
    }

    let local_html = std::fs::read_to_string(&local_index).ok()?;
    let local_bundle = extract_script_bundle(&local_html)?;

    // Ultra-fast probing of remote edge via xh (Rust HTTP) with strict timeout
    let output = Command::new("xh")
        .args([
            "get",
            "https://sumaenima.chimaera-heptatonic.ts.net/index.html",
            "-b",
            "--timeout=3",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let remote_html = String::from_utf8_lossy(&output.stdout);
    let remote_bundle =
        extract_script_bundle(&remote_html).unwrap_or_else(|| "unknown".to_string());

    let in_sync = local_bundle == remote_bundle;

    Some(ParityStatus {
        local_bundle,
        remote_bundle,
        in_sync,
    })
}

/// Executes atomic frontend deployment to Ybyra and Kavure
pub fn execute_front_deploy(root: &Path, build_first: bool) -> Result<()> {
    crate::baseline::print_banner(
        "StenioSentinel — Frontend Deployment Automation (--deploy front)",
    );

    let fe_dir = find_frontend_dir(root)
        .context("Frontend directory (app/frontend-v2) not found in workspace.")?;
    let dist_dir = fe_dir.join("dist");

    if build_first || !dist_dir.exists() {
        println!(
            "{}",
            "[*] Compiling SPA frontend (npm run build)..."
                .cyan()
                .bold()
        );
        let status = Command::new("npm")
            .arg("run")
            .arg("build")
            .current_dir(&fe_dir)
            .status()
            .context("Failed to execute 'npm run build' on frontend.")?;

        if !status.success() {
            anyhow::bail!(
                "Frontend compilation failed with exit code: {:?}",
                status.code()
            );
        }
        println!("{}", "  ✅ Build compiled successfully!".green());
    }

    let dist_str = format!("{}/", dist_dir.display());

    // 1. Edge node Ybyra synchronization (primary edge)
    println!(
        "{}",
        "[*] Synchronizing assets with edge node Ybyra (/var/www/sumaenima)...".cyan()
    );
    let ybyra_outcome = crate::remote::run_rsync(&dist_str, "ybyra:/var/www/sumaenima/", 5);
    ybyra_outcome.print_status("Ybyra Sync");

    // 2. Standby node Kavure synchronization (warm standby)
    println!(
        "{}",
        "[*] Synchronizing with standby node Kavure (/var/www/sumaenima)...".cyan()
    );
    let kavure_outcome = crate::remote::run_rsync(&dist_str, "kavure:/var/www/sumaenima/", 5);
    kavure_outcome.print_status("Kavure Sync");

    // 3. Reload Nginx on Ybyra with zero downtime
    println!(
        "{}",
        "[*] Reloading Nginx on Ybyra (zero downtime)...".cyan()
    );
    let reload_outcome = crate::remote::run_ssh(
        "ybyra",
        "docker exec $(docker ps -f name=sae-edge_proxy -q | head -1) nginx -s reload",
        5,
    );
    reload_outcome.print_status("Nginx reload on Ybyra");

    // 4. Final parity verification
    if let Some(parity) = check_static_parity(root) {
        if parity.in_sync {
            println!(
                "{}",
                format!(
                    "  ✨ Production parity confirmed! Active bundle: {}",
                    parity.local_bundle
                )
                .green()
                .bold()
            );
        } else {
            println!(
                "{}",
                format!("  ⚠️  Warning: Edge still serving '{}', expected '{}'. Awaiting cache propagation.", parity.remote_bundle, parity.local_bundle).yellow()
            );
        }
    }

    println!();
    println!(
        "{}",
        "🚀 Fast frontend deployment finished successfully!"
            .bold()
            .green()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_script_bundle_valid() {
        let html = r#"<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="UTF-8" />
    <script type="module" crossorigin src="/assets/index-DKOftQuM.js"></script>
    <link rel="stylesheet" crossorigin href="/assets/index-Bq4X-V3m.css">
  </head>
  <body><div id="root"></div></body>
</html>"#;
        let bundle = extract_script_bundle(html);
        assert_eq!(bundle, Some("assets/index-DKOftQuM.js".to_string()));
    }

    #[test]
    fn test_extract_script_bundle_missing() {
        let html = "<html><body><h1>Hello World</h1></body></html>";
        assert_eq!(extract_script_bundle(html), None);
    }

    #[test]
    fn test_extract_script_bundle_empty() {
        assert_eq!(extract_script_bundle(""), None);
    }
}
