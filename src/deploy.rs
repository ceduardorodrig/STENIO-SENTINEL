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

/// Extrai o nome do bundle principal de script (assets/index-*.js) a partir do HTML
pub fn extract_script_bundle(html: &str) -> Option<String> {
    let re = Regex::new(r#"assets/index-[A-Za-z0-9_-]+\.js"#).ok()?;
    re.find(html).map(|m| m.as_str().to_string())
}

/// Localiza o diretório do frontend no workspace
pub fn find_frontend_dir(root: &Path) -> Option<PathBuf> {
    let candidates = [
        root.join("sumaenimahub/sumaenima-hub/app/frontend-v2"),
        root.join("app/frontend-v2"),
        PathBuf::from("/mnt/NVME_PCI/agentic-ai/sumaenimahub/sumaenima-hub/app/frontend-v2"),
    ];

    for candidate in candidates {
        if candidate.exists() && candidate.join("package.json").exists() {
            return Some(candidate);
        }
    }
    None
}

/// Audita a paridade entre o bundle local compilado e a borda remota no Ybyra
pub fn check_static_parity(root: &Path) -> Option<ParityStatus> {
    let fe_dir = find_frontend_dir(root)?;
    let local_index = fe_dir.join("dist/index.html");

    if !local_index.exists() {
        return None;
    }

    let local_html = std::fs::read_to_string(&local_index).ok()?;
    let local_bundle = extract_script_bundle(&local_html)?;

    // Sondagem ultrarrápida da borda remota via xh (Rust HTTP) com timeout estrito
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
        extract_script_bundle(&remote_html).unwrap_or_else(|| "desconhecido".to_string());

    let in_sync = local_bundle == remote_bundle;

    Some(ParityStatus {
        local_bundle,
        remote_bundle,
        in_sync,
    })
}

/// Executa a sincronização atômica do frontend para Ybyra e Kavure
pub fn execute_front_deploy(root: &Path, build_first: bool) -> Result<()> {
    crate::baseline::print_banner(
        "StênioSentinel — Automação de Deploy do Frontend (--deploy front)",
    );

    let fe_dir = find_frontend_dir(root)
        .context("Diretório do frontend (app/frontend-v2) não encontrado no workspace.")?;
    let dist_dir = fe_dir.join("dist");

    if build_first || !dist_dir.exists() {
        println!(
            "{}",
            "[*] Compilando frontend SPA (npm run build)..."
                .cyan()
                .bold()
        );
        let status = Command::new("npm")
            .arg("run")
            .arg("build")
            .current_dir(&fe_dir)
            .status()
            .context("Falha ao executar 'npm run build' no frontend.")?;

        if !status.success() {
            anyhow::bail!(
                "Compilação do frontend falhou com exit code: {:?}",
                status.code()
            );
        }
        println!("{}", "  ✅ Build compilado com sucesso!".green());
    }

    let dist_str = format!("{}/", dist_dir.display());

    // 1. Sincronização Ybyra (Edge primário)
    println!(
        "{}",
        "[*] Sincronizando assets com nó de borda Ybyra (/var/www/sumaenima)...".cyan()
    );
    let ybyra_outcome = crate::remote::run_rsync(&dist_str, "ybyra:/var/www/sumaenima/", 5);
    ybyra_outcome.print_status("Sincronização Ybyra");

    // 2. Sincronização Kavure (Warm standby)
    println!(
        "{}",
        "[*] Sincronizando com nó standby Kavure (/var/www/sumaenima)...".cyan()
    );
    let kavure_outcome = crate::remote::run_rsync(&dist_str, "kavure:/var/www/sumaenima/", 5);
    kavure_outcome.print_status("Sincronização Kavure");

    // 3. Recarrega Nginx no Ybyra sem downtime
    println!(
        "{}",
        "[*] Recarregando Nginx no Ybyra (zero downtime)...".cyan()
    );
    let reload_outcome = crate::remote::run_ssh(
        "ybyra",
        "docker exec $(docker ps -f name=sae-edge_proxy -q | head -1) nginx -s reload",
        5,
    );
    reload_outcome.print_status("Recarga Nginx no Ybyra");

    // 4. Verificação final de paridade
    if let Some(parity) = check_static_parity(root) {
        if parity.in_sync {
            println!(
                "{}",
                format!(
                    "  ✨ Paridade confirmada em produção! Bundle ativo: {}",
                    parity.local_bundle
                )
                .green()
                .bold()
            );
        } else {
            println!(
                "{}",
                format!("  ⚠️  Aviso: Borda ainda responde '{}', esperado '{}'. Aguarde propagação do cache.", parity.remote_bundle, parity.local_bundle).yellow()
            );
        }
    }

    println!();
    println!(
        "{}",
        "🚀 Deploy rápido de frontend finalizado com sucesso!"
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
