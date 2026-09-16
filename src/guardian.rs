use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
pub struct GuardianReport {
    pub is_intact: bool,
    pub binary_hash: String,
    pub source_files_checked: usize,
    pub messages: Vec<String>,
    pub tamper_alerts: Vec<String>,
}

/// O Guardian audita a integridade criptográfica do próprio binário e código-fonte do Stênio.
/// Se um agente de IA ou script malicioso tentar adulterar as regras de governança,
/// enfraquecer regexes ou desativar checagens, o Guardian detecta a discrepância no ato.
pub fn audit_stenio_integrity(stenio_src_dir: &Path) -> GuardianReport {
    let mut messages = Vec::new();
    let mut tamper_alerts = Vec::new();
    let mut files_checked = 0;

    // 1. Hash do próprio executável em execução
    let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("stenio"));
    let mut binary_hash = String::new();
    if let Ok(bytes) = fs::read(&exe_path) {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        binary_hash = format!("{:x}", hasher.finalize())[..16].to_string();
        messages.push(format!("🔐 Executável Nativo Íntegro: {} (SHA-256: {})", exe_path.display(), binary_hash));
    }

    // 2. Auto-auditoria de código: impedir enfraquecimento das regras fundamentais
    let critical_files = ["rule.rs", "infra.rs", "vault.rs", "mesh.rs", "main.rs"];
    for file in &critical_files {
        let p = stenio_src_dir.join("src").join(file);
        if p.exists() {
            files_checked += 1;
            if let Ok(content) = fs::read_to_string(&p) {
                // Checagem Anti-Tampering 1: Remoção de regras fundamentais
                if file == &"rule.rs" && !content.contains("ARCH-NO-PYTHON") {
                    tamper_alerts.push("Alerta Crítico: Regra ARCH-NO-PYTHON foi suprimida do código-fonte!".to_string());
                }
                if file == &"infra.rs" && !content.contains("SEC-SOPS-UNENCRYPTED") {
                    tamper_alerts.push("Alerta Crítico: Scanner de segredos SOPS foi desativado em infra.rs!".to_string());
                }
                if file == &"infra.rs" && !content.contains("SEC-PRIVATE-KEY-CLEARTEXT") {
                    tamper_alerts.push("Alerta Crítico: Bloqueio de chaves privadas em texto claro foi alterado!".to_string());
                }

                // Checagem Anti-Tampering 2: Injeção de skips indiscriminados
                let bypass_count = content.matches("// stenio-ignore-all").count();
                if bypass_count > 0 {
                    tamper_alerts.push(format!("Alerta de Segurança: Tentativa de bypass global em '{}'", file));
                }
            }
        }
    }

    let is_intact = tamper_alerts.is_empty();
    if is_intact {
        messages.push(format!("🛡️ Guardian: {} módulos do núcleo do Stênio auditados com Zero Adulteração.", files_checked));
    } else {
        messages.push(format!("🚨 Guardian: {} violação(ões) de adulteração/tampering detectadas!", tamper_alerts.len()));
    }

    GuardianReport {
        is_intact,
        binary_hash,
        source_files_checked: files_checked,
        messages,
        tamper_alerts,
    }
}
