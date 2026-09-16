use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Default)]
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
        // 1. Suporte a comentário inline com regra específica: # stenio-ignore: RULE_ID
        if line_content.contains("# stenio-ignore") || line_content.contains("// stenio-ignore") {
            if line_content.contains(rule_id) || line_content.contains("all") {
                return true;
            }
        }

        // 2. nosemgrep: compatível com semgrep CLI, com proteção adicional para SEC-*
        //
        // Comportamento:
        //   # nosemgrep: SEC-SUDO        → NUNCA ignora (SEC-* são absolutas)
        //   # nosemgrep: ARCH-RUST-TOOLS → ignora apenas ARCH-RUST-TOOLS
        //   # nosemgrep                  → ignora para regras não-SEC-* (compat. semgrep)
        //                                  NÃO ignora para regras SEC-* (segurança absoluta)
        if line_content.contains("# nosemgrep") || line_content.contains("// nosemgrep") {
            // Regras de segurança (SEC-*) são absolutas — nem nosemgrep genérico pode suprimi-las.
            // Apenas stenio-ignore: RULE_ID pode ignorá-las, e mesmo assim registra no log.
            if rule_id.starts_with("SEC-") {
                return false;
            }
            // Para regras não-SEC, nosemgrep com rule_id específico ignora apenas aquela regra.
            // nosemgrep genérico (sem ":") mantém compatibilidade com o ecossistema semgrep.
            if let Some(after) = line_content.split("nosemgrep").nth(1) {
                let trimmed_after = after.trim();
                if trimmed_after.is_empty() || !trimmed_after.starts_with(':') {
                    // nosemgrep genérico — ignora para regras não-SEC
                    return true;
                }
                // nosemgrep: RULE_ID — ignora apenas se rule_id bater
                if trimmed_after.contains(rule_id) {
                    return true;
                }
                // nosemgrep: OUTRA_REGRA — não ignora esta regra
                return false;
            }
            return true; // fallback: nosemgrep sem after → ignora (compatibilidade)
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
