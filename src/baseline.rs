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
        // 1. Suporte a comentário inline no código: # stenio-ignore: RULE_ID ou # nosemgrep
        if line_content.contains("# stenio-ignore") || line_content.contains("// stenio-ignore") {
            if line_content.contains(rule_id) || line_content.contains("all") {
                return true;
            }
        }
        if line_content.contains("# nosemgrep") || line_content.contains("// nosemgrep") {
            return true;
        }

        // 2. Checa whitelist de arquivo
        for pattern in &self.ignored_patterns {
            if file_path.contains(pattern) {
                return true;
            }
        }

        false
    }
}
