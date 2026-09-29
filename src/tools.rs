//! Audita as ferramentas de operação contra o que o repositório versiona.
//!
//! # Por que existe (29/09/2026)
//!
//! As ferramentas de operação (`config-backup`, `zomboid-*`, `smart-metrics`, …)
//! existiam **apenas** em `/usr/local/bin`, fora de qualquer repositório. O motor
//! audita arquivos do repositório — nunca o sistema de arquivos — então ele não
//! tinha como vê-las. Três custos reais e medidos desse ponto cego:
//!
//! 1. `smart-metrics.py` violou `ARCH-NO-PYTHON` em 3 hosts por semanas, sem que
//!    nenhum gate acusasse (o arquivo não estava no repo).
//! 2. `scryfall-prefetch` vivia em `/tmp`, evaporou num reboot e a população do
//!    mirror ficou congelada em ~62% por quase um mês.
//! 3. Um `scryfall-prefetch` instalado estava **corrompido** (variáveis apagadas)
//!    e ninguém percebeu — não havia versão anterior para comparar.
//!
//! # Como funciona
//!
//! A fonte da verdade é o próprio repositório: `provisioning/scripts/` (ferramentas
//! de operação) e `provisioning/<crate>/` (ferramentas Rust). O instalador
//! `install-homelab-tools.sh` mantém o mapa do que é conhecido — é dele que este
//! auditor lê, para que não existam duas listas divergindo.
//!
//! O veredito por ferramenta:
//!
//! | Situação | Veredito |
//! |---|---|
//! | Está no host E no repo | ✅ conforme |
//! | Está no host e NÃO no repo | ⚠️ **órfã** — candidata a migração |
//! | Binário de terceiro / pacote do sistema | ignorado por allowlist |
//!
//! Não tenta ser esperto com heurística: prefere uma allowlist explícita, que é
//! auditável e não gera ruído.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Binários de terceiros e pacotes do sistema que legitimamente vivem em
/// `/usr/local/bin` sem serem código deste ecossistema.
const ALLOWLIST: &[&str] = &[
    "bat",
    "fd",
    "apt",
    "gnome-help",
    "yelp",
    "highlight-mint",
    "search",
    "ollama",
    "mkinitcpio",
    "remove-nvidia",
];

/// Binários Rust cujo crate é versionado em OUTRO lugar do repositório (não em
/// `provisioning/scripts/`, porque não são scripts).
const KNOWN_ELSEWHERE: &[&str] = &["gpu-supervisor", "with-smooth-motion"];

struct Report {
    hosts: Vec<HostResult>,
}

struct HostResult {
    host: String,
    /// Ferramentas presentes no host.
    present: BTreeSet<String>,
    /// Ferramentas que o repositório versiona.
    declared: BTreeSet<String>,
    /// Erro de acesso ao host, quando houver.
    error: Option<String>,
}

impl HostResult {
    /// Ferramentas no host que o repositório não conhece — o achado que importa.
    fn orphans(&self) -> Vec<&String> {
        self.present
            .iter()
            .filter(|f| !self.declared.contains(*f))
            .collect()
    }

    /// Ferramentas declaradas que não estão no host.
    fn missing(&self) -> Vec<&String> {
        self.declared
            .iter()
            .filter(|f| !self.present.contains(*f))
            .collect()
    }
}

pub fn run_tools_audit(repo_root: &Path) -> anyhow::Result<()> {
    println!();
    println!("══════════════════════════════════════════════════════════════════════════════");
    println!("  🧰 StênioKernel — Ferramentas de Operação (--tools)");
    println!("══════════════════════════════════════════════════════════════════════════════");
    println!("  Cruza /usr/local/bin de cada host com o que `provisioning/` versiona.");
    println!("  Órfã = existe no host mas não no repositório (sem diff, sem revisão).");
    println!();

    let declared = read_declared_tools(repo_root);
    if declared.is_empty() {
        println!("  ⚠️  nenhuma ferramenta declarada encontrada.");
        println!(
            "     Esperado: {}/provisioning/scripts/install-homelab-tools.sh",
            repo_root.display()
        );
        println!("     Sem essa lista não há como cruzar host × repositório.");
        println!();
        return Ok(());
    }
    println!(
        "  Fonte da verdade: provisioning/ ({} ferramentas declaradas)",
        declared.len()
    );
    println!();

    let hosts = ["psicopompo", "kavure", "kuaray", "ybyra", "ybytu"];
    let mut report = Report { hosts: Vec::new() };

    for host in hosts {
        let present = list_host_tools(host);
        let (present, error) = match present {
            Ok(p) => (p, None),
            Err(e) => (BTreeSet::new(), Some(e)),
        };
        report.hosts.push(HostResult {
            host: host.to_string(),
            present,
            declared: declared.clone(),
            error,
        });
    }

    let mut total_orphans = 0usize;
    for h in &report.hosts {
        print_host(h);
        total_orphans += h.orphans().len();
    }

    println!("──────────────────────────────────────────────────────────────────────────────");
    if total_orphans == 0 {
        println!("  ✅ Nenhuma ferramenta órfã: todo o operacional está versionado.");
        println!("     O que roda em /usr/local/bin também existe em provisioning/,");
        println!("     então passa por gate, revisão e histórico como o resto do código.");
    } else {
        println!(
            "  ⚠️  {total_orphans} ferramenta(s) órfã(s) — sem diff, sem revisão, invisível ao gate."
        );
        println!("     Migrar para provisioning/scripts/ e instalar via");
        println!("     `install-homelab-tools.sh` (ver mnemocine/guides/stenio-ci-unificado.md).");
    }
    println!();

    Ok(())
}

fn print_host(h: &HostResult) {
    println!("  [NÓ] {}", h.host);
    if let Some(err) = &h.error {
        println!("       ✗ inacessível: {err}");
        return;
    }

    let orphans = h.orphans();
    if orphans.is_empty() {
        println!("       ✅ todas as ferramentas presentes estão versionadas");
    } else {
        for o in orphans {
            println!("       ⚠️  {o} — NÃO versionada (candidata a migração)");
        }
    }

    // Ferramentas declaradas mas ausentes no host: pode ser normal (cada host tem
    // o seu papel), então é informativo e não alarme.
    let missing = h.missing();
    if !missing.is_empty() {
        println!(
            "       ℹ️  {} declarada(s) e ausente(s) neste nó (normal: papel do host)",
            missing.len()
        );
    }
}

/// Lista as ferramentas em `/usr/local/bin`, filtrando allowlist e backups.
///
/// Localmente usa `std::fs`; remotamente usa o driver canônico
/// `crate::remote::run_ssh` — obrigatório pela regra `RUST-CANONICAL-REMOTE`,
/// que existe para garantir isolamento de timeout, `BatchMode` e detecção de
/// re-auth do Tailscale SSH num único lugar.
fn list_host_tools(host: &str) -> Result<BTreeSet<String>, String> {
    let is_local = host_matches_local(host);

    let listing = if is_local {
        fs::read_dir("/usr/local/bin")
            .map_err(|e| format!("read_dir: {e}"))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        match crate::remote::run_ssh(host, "ls -1 /usr/local/bin 2>/dev/null", 8) {
            crate::remote::RemoteOutcome::Success(out) => out,
            crate::remote::RemoteOutcome::AuthRequired { .. } => {
                return Err("SSH exige re-autenticação (Tailscale check mode)".to_string());
            }
            crate::remote::RemoteOutcome::Timeout { timeout_secs, .. } => {
                return Err(format!("ssh: timeout após {timeout_secs}s"));
            }
            crate::remote::RemoteOutcome::Unreachable { reason, .. } => {
                return Err(format!("ssh inacessível: {reason}"));
            }
            crate::remote::RemoteOutcome::Failed { exit_code, .. } => {
                return Err(format!("ssh falhou (exit={exit_code:?})"));
            }
        }
    };

    let mut tools = BTreeSet::new();
    for line in listing.lines() {
        let name = line.trim();
        if name.is_empty() {
            continue;
        }
        if is_ignored(name) {
            continue;
        }
        tools.insert(name.to_string());
    }
    Ok(tools)
}

/// Decide se um arquivo em `/usr/local/bin` deve ser ignorado na auditoria.
fn is_ignored(name: &str) -> bool {
    // Backups deixados deliberadamente por migrações (documentados no commit).
    if name.contains(".bak-") || name.ends_with(".disabled") {
        return true;
    }
    // Binários de terceiros / pacotes do sistema.
    if ALLOWLIST.contains(&name) {
        return true;
    }
    // Crates versionados em outros pontos do repositório.
    if KNOWN_ELSEWHERE.contains(&name) {
        return true;
    }
    false
}

/// Compara o hostname com o nó local, tolerando a capitalização do psicopompo.
fn host_matches_local(host: &str) -> bool {
    let local = std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            fs::read_to_string("/proc/sys/kernel/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default()
        .to_ascii_lowercase();
    host.eq_ignore_ascii_case(&local)
}

/// Lê as ferramentas declaradas do instalador canônico.
///
/// O instalador mantém dois mapas bash (`RUST_TOOLS` e `SHELL_TOOLS`). Ler dali —
/// em vez de manter uma lista paralela em Rust — garante que auditar e instalar
/// nunca divirjam. É parsing simples de linha, não um interpretador de bash.
fn read_declared_tools(repo_root: &Path) -> BTreeSet<String> {
    let installer = repo_root.join("provisioning/scripts/install-homelab-tools.sh");
    let mut set = BTreeSet::new();

    let Ok(content) = fs::read_to_string(&installer) else {
        return set;
    };

    for line in content.lines() {
        let t = line.trim();
        // Formato das entradas: `[nome]=nome`
        if !t.starts_with('[') || !t.contains("]=") {
            continue;
        }
        if let Some(end) = t.find(']') {
            let name = &t[1..end];
            // Ignora a chave `--help` e afins; nomes vêm só do mapa de ferramentas.
            if !name.is_empty() && !name.starts_with('-') {
                set.insert(name.to_string());
            }
        }
    }

    // Ferramentas Rust também têm o diretório do crate como declaração, mesmo que
    // o map do bash use outro nome. Varre `provisioning/*/Cargo.toml`.
    if let Ok(entries) = fs::read_dir(repo_root.join("provisioning")) {
        for e in entries.flatten() {
            let p = e.path();
            if p.join("Cargo.toml").is_file()
                && let Some(name) = p.file_name().and_then(|n| n.to_str())
            {
                set.insert(name.to_string());
            }
        }
    }

    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignora_backups_e_allowlist() {
        assert!(is_ignored("config-backup.bak-20260929"));
        assert!(is_ignored("scryfall-prefetch.disabled"));
        assert!(is_ignored("bat"));
        assert!(is_ignored("fd"));
        assert!(is_ignored("gpu-supervisor"));
        assert!(is_ignored("with-smooth-motion"));
    }

    #[test]
    fn nao_ignora_ferramenta_nossa() {
        assert!(!is_ignored("config-backup"));
        assert!(!is_ignored("zomboid-backup"));
        assert!(!is_ignored("smart-metrics"));
    }

    #[test]
    fn le_mapas_do_instalador() {
        let dir = std::env::temp_dir().join("stenio-tools-test");
        let scripts = dir.join("provisioning/scripts");
        let _ = fs::create_dir_all(&scripts);
        let _ = fs::write(
            scripts.join("install-homelab-tools.sh"),
            "declare -A SHELL_TOOLS=(\n    [config-backup]=config-backup\n    [zomboid-backup]=zomboid-backup\n)\n",
        );
        let got = read_declared_tools(&dir);
        assert!(got.contains("config-backup"));
        assert!(got.contains("zomboid-backup"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_local_e_reconhecido_sem_ssh() {
        // O nó atual precisa ser tratado como local para não depender de ssh.
        let me = std::env::var("HOSTNAME").unwrap_or_default();
        if !me.is_empty() {
            assert!(host_matches_local(&me));
        }
    }
}
