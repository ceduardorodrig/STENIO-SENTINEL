use serde::Deserialize;
use std::fs;
use std::path::Path;

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct GeneralConfig {
    pub name: Option<String>,
    pub version: Option<String>,
    pub min_laws_count: Option<usize>,
    pub agents_md: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct SecurityConfig {
    pub banned_python_packages: Option<Vec<String>>,
    pub prohibit_bare_sudo: Option<bool>,
    pub scan_hardcoded_secrets: Option<bool>,
    pub forbid_eval_exec: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ArchitectureConfig {
    pub banned_modules: Option<Vec<String>>,
    pub prefer_rust_tools: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct FrontendConfig {
    pub enforce_zustand_shallow: Option<bool>,
    pub enforce_useeffect_cleanup: Option<bool>,
    pub enforce_audioworklet_samplerate: Option<bool>,
    pub enforce_wakelock_release: Option<bool>,
    pub enforce_m3_typography: Option<String>,
    pub forbid_bare_dividers: Option<bool>,
    pub forbid_silent_console_errors: Option<bool>,
    pub forbid_debug_console_logs: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct GpuConfig {
    pub cache_dir: Option<String>,
    pub active_whisper_model: Option<String>,
    pub min_model_size_mb: Option<u64>,
    pub banned_bloat_dirs: Option<Vec<String>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct DocsConfig {
    pub enforce_doc_anchors: Option<bool>,
    pub doc_anchor_prefix: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct DryConfig {
    pub enabled: Option<bool>,
    pub min_lines: Option<usize>,
    pub strict: Option<bool>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct TopologyConfig {
    pub authorized_hub_nodes: Option<Vec<String>>,
    pub edge_nodes: Option<Vec<String>>,
    pub backend_nodes: Option<Vec<String>>,
    pub dev_gpu_nodes: Option<Vec<String>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct CustomRuleConfig {
    pub id: String,
    pub tag: Option<String>,
    pub severity: Option<String>,
    pub name: String,
    pub description: String,
    pub pattern: String,
    pub extensions: Vec<String>,
    pub must_match: Option<bool>,
    pub suggestion: Option<String>,
    pub fix_replacement: Option<String>,
    pub path_include: Option<Vec<String>>,
    pub path_exclude: Option<Vec<String>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct SteniocheckConfig {
    pub general: Option<GeneralConfig>,
    pub security: Option<SecurityConfig>,
    pub architecture: Option<ArchitectureConfig>,
    pub frontend: Option<FrontendConfig>,
    pub gpu: Option<GpuConfig>,
    pub docs: Option<DocsConfig>,
    pub dry: Option<DryConfig>,
    pub topology: Option<TopologyConfig>,
    pub custom_rules: Option<Vec<CustomRuleConfig>>,
}

impl SteniocheckConfig {
    pub fn load_from_dir(repo_root: &Path) -> Self {
        let toml_path = repo_root.join("steniocheck.toml");
        if toml_path.is_file() {
            if let Ok(content) = fs::read_to_string(&toml_path) {
                if let Ok(config) = toml::from_str::<SteniocheckConfig>(&content) {
                    return config;
                }
            }
        }
        Self::default()
    }
}
