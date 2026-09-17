use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct Whitelist {
    ignored_patterns: HashSet<String>,
}

impl Whitelist {
    pub fn load_from_file(path: &Path) -> Self {
        let mut ignored_patterns = HashSet::new();
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(obj) = val.as_object() {
                        for (file_key, _) in obj {
                            ignored_patterns.insert(file_key.clone());
                        }
                    }
                }
            }
        }
        Self { ignored_patterns }
    }

    pub fn is_ignored(&self, file_path: &str, rule_id: &str, line_content: &str) -> bool {
        // Regras Canônicas Invioláveis: NUNCA podem ser ignoradas por comentário inline,
        // nem por IAs, nem por humanos. Tentativas de supressão são rejeitadas.
        let is_inviolable = rule_id.starts_with("SEC-")
            || rule_id.starts_with("AGENT-")
            || rule_id.starts_with("ARCH-")
            || rule_id.starts_with("RUST-")
            || rule_id.starts_with("CONF-")
            || rule_id == "TEST-NO-SILENT-SKIP";

        if is_inviolable {
            return false;
        }

        // 1. Suporte a comentário inline com regra específica: # stenio-ignore: RULE_ID
        // NOTA DE SEGURANÇA: 'stenio-ignore: all' é expressamente PROIBIDO e não tem efeito.
        if line_content.contains("# stenio-ignore") || line_content.contains("// stenio-ignore") {
            // Proibição estrita de bypass global 'all'
            if line_content.contains("stenio-ignore: all") || line_content.contains("stenio-ignore:all") {
                return false;
            }
            if line_content.contains(rule_id) {
                return true;
            }
        }

        // 2. nosemgrep: compatível com semgrep CLI (apenas regras específicas não-críticas)
        if line_content.contains("# nosemgrep") || line_content.contains("// nosemgrep") {
            if let Some(after) = line_content.split("nosemgrep").nth(1) {
                let trimmed_after = after.trim();
                if trimmed_after.is_empty() || !trimmed_after.starts_with(':') {
                    // nosemgrep genérico é proibido para evitar supressão cega por IAs
                    return false;
                }
                // nosemgrep: RULE_ID — ignora apenas se rule_id bater
                if trimmed_after.contains(rule_id) {
                    return true;
                }
                return false;
            }
            return false;
        }

        // 3. Checa whitelist de arquivo (.steniocheck-whitelist-registry.json)
        for pattern in &self.ignored_patterns {
            if file_path.contains(pattern) {
                return true;
            }
        }

        false
    }
}
