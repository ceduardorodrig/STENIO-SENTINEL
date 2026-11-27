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
    /// Why this local build must not replace production; `None` when it may.
    pub deploy_block: Option<String>,
}

/// Why the local build must not be deployed (GB-324): it is older than what production serves,
/// older than its own sources, or one of the two ages cannot be established. Times are Unix
/// seconds; `production` is the `Last-Modified` of the served `index.html`, which `rsync -a`
/// keeps equal to the modification time of the deployed build.
pub fn deploy_block(
    local: Option<i64>,
    production: Option<i64>,
    stale: Option<String>,
) -> Option<String> {
    if let Some(why) = stale {
        return Some(why);
    }
    let Some(local) = local else {
        return Some("the age of the local build cannot be established".to_string());
    };
    let Some(production) = production else {
        return Some("the age of the production build cannot be established".to_string());
    };
    let utc = |secs: i64| {
        chrono::DateTime::from_timestamp(secs, 0)
            .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_default()
    };
    (local < production).then(|| {
        format!(
            "the local build ({}) is older than the one production serves ({})",
            utc(local),
            utc(production)
        )
    })
}

fn modified_secs(file: &Path) -> Option<i64> {
    let time = std::fs::metadata(file).and_then(|m| m.modified()).ok()?;
    let since = time.duration_since(std::time::UNIX_EPOCH).ok()?;
    i64::try_from(since.as_secs()).ok()
}

/// Splits `xh --print=hb` output into the `Last-Modified` time and the body.
fn parse_probe(response: &str) -> (Option<i64>, &str) {
    let split = response
        .find("\r\n\r\n")
        .map(|i| (i, i + 4))
        .into_iter()
        .chain(response.find("\n\n").map(|i| (i, i + 2)))
        .min();
    let Some((end, body)) = split else {
        return (None, response);
    };
    let modified = response[..end].lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("last-modified") {
            return None;
        }
        chrono::DateTime::parse_from_rfc2822(value.trim())
            .ok()
            .map(|t| t.timestamp())
    });
    (modified, &response[body..])
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
            "--print=hb",
            "--check-status",
            "--timeout=3",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let response = String::from_utf8_lossy(&output.stdout);
    let (production, remote_html) = parse_probe(&response);
    let remote_bundle = extract_script_bundle(remote_html).unwrap_or_else(|| "unknown".to_string());

    let in_sync = local_bundle == remote_bundle;

    Some(ParityStatus {
        local_bundle,
        remote_bundle,
        in_sync,
        deploy_block: deploy_block(
            modified_secs(&local_index),
            production,
            crate::hostops::stale_build(&fe_dir),
        ),
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

    // Nothing leaves this host unless the build is provably not older than production.
    let refusal = match check_static_parity(root) {
        Some(parity) => parity.deploy_block,
        None => Some(
            "production or the local bundle cannot be read, so their ages are unknown".to_string(),
        ),
    };
    if let Some(why) = refusal {
        anyhow::bail!("Deploy refused: {why}. Nothing was synchronized.");
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
    fn a_build_is_deployable_only_when_not_older_than_production() {
        assert!(deploy_block(Some(200), Some(100), None).is_none());
        assert!(deploy_block(Some(100), Some(100), None).is_none());
        assert!(deploy_block(Some(100), Some(200), None).is_some());
        assert!(deploy_block(Some(200), None, None).is_some());
        assert!(deploy_block(None, Some(100), None).is_some());
        assert!(deploy_block(Some(200), Some(100), Some("stale".into())).is_some());
    }

    #[test]
    fn the_probe_keeps_the_body_and_reads_the_date() {
        let (when, body) = parse_probe(
            "HTTP/2.0 200 OK\nlast-modified: Fri, 27 Nov 2026 07:49:44 GMT\n\n<html>\n\n</html>",
        );
        assert_eq!(when, Some(1_795_765_784));
        assert_eq!(body, "<html>\n\n</html>");
        assert_eq!(parse_probe("HTTP/1.1 200 OK\n\nx").0, None);
    }

    #[test]
    fn test_extract_script_bundle_empty() {
        assert_eq!(extract_script_bundle(""), None);
    }
}
