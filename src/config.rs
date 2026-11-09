use serde::Deserialize;
use std::fs;
use std::path::Path;

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct GeneralConfig {
    pub name: Option<String>,
    pub version: Option<String>,
    pub scope: Option<String>,
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

/// `[frappe]` table: static rules over a Frappe app tree (`--scope frappe`) and the
/// post-deploy checks of `stenio verify-release`. No project name lives in the engine.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct FrappeConfig {
    /// App package directory name (the folder with `hooks.py`); inferred when absent.
    pub app: Option<String>,
    /// File holding the registered test list (absolute, or relative to the repo root).
    pub test_list_file: Option<String>,
    /// Heading line that opens the section of that file listing the tests.
    pub test_list_anchor: Option<String>,
    /// Release battery script whose `names`/`cmds` arrays run the pure tests (absolute, or
    /// relative to the app root). Absent, the engine looks for `scripts/release-checks.sh` next
    /// to the app and then for the nearest one above it; env `STENIO_FRAPPE_BATTERY` wins.
    pub battery_file: Option<String>,
    /// Rehearsal script whose per-module verdict `FRAPPE-REHEARSAL-VERDICT` reads (absolute, or
    /// relative to the app root). Absent, the engine looks for `scripts/rehearse.sh` and then for
    /// the nearest one above the app; env `STENIO_FRAPPE_REHEARSAL` wins.
    pub rehearsal_file: Option<String>,
    /// Release orchestrator whose step order `FRAPPE-RELEASE-ORDER` reads (absolute, or relative
    /// to the app root). Absent, the engine looks for `scripts/release.sh`,
    /// `compose/frappe/scripts/release.sh` and then the nearest one above the app; env
    /// `STENIO_FRAPPE_RELEASE` wins.
    pub release_file: Option<String>,
    /// File listing DocTypes that need no sidebar entry (`Name | reason` per line).
    pub sidebar_allowlist: Option<String>,
    /// Roles that exist without a fixture (added to the built-in Frappe core list).
    pub role_allowlist: Option<Vec<String>>,
    /// Link targets that are not checked for a title field (added to the core list).
    pub link_allowlist: Option<Vec<String>>,
    /// Extra substrings that count as a permission check in a whitelisted function.
    pub permission_markers: Option<Vec<String>>,
    /// Whitelisted endpoints called by an outside client (dotted path or function name); exempt from `FRAPPE-WHITELIST-NO-CALLER`.
    pub whitelist_external: Option<Vec<String>>,
    /// Catalogue used by the sidebar and Select rules, relative to the package.
    pub locale_file: Option<String>,
    /// Docker image repository (verify-release).
    pub image: Option<String>,
    /// Frappe site name (verify-release).
    pub site: Option<String>,
    /// URL of the ping endpoint as seen from the deploy host (verify-release).
    pub ping_url: Option<String>,
    /// Public entry point the site must advertise as `host_name` (verify-release).
    pub public_url: Option<String>,
    /// Compose project name of rehearsal stacks (verify-release).
    pub rehearsal_project: Option<String>,
    /// Shell glob of rehearsal directories on the host (verify-release).
    pub rehearsal_dir_glob: Option<String>,
    /// Shell glob of the scheduled (timer-driven) database dumps on the host (verify-release).
    pub scheduled_backup_glob: Option<String>,
    /// Age limit in hours for the scheduled dump (verify-release; default 26, the timer period plus slack).
    pub scheduled_backup_max_age_hours: Option<u64>,
    /// Tag of the custom rules run by `pre-release` (`stenio --tag <tag> --strict --compact`).
    pub custom_rules_tag: Option<String>,
    /// Technical strings (Select options, labels) that need no translation.
    pub label_allowlist: Option<Vec<String>>,
    /// JSON files (path substrings) a patch force-reloads, exempt from the `modified` bump rule.
    pub modified_allowlist: Option<Vec<String>>,
    /// `FRAPPE-FETCH-PARITY` (GB-241): child DocTypes whose `field` must declare `fetch_from`.
    pub fetch_parity: Option<Vec<FetchParity>>,
}

/// One `[[frappe.fetch_parity]]` entry: every child DocType whose snake_case name matches
/// `doctype_pattern` (`*` wildcard, e.g. `*_member`) must declare `field` with
/// `fetch_from = fetch_from` and, unless `fetch_if_empty = false`, `fetch_if_empty: 1`.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct FetchParity {
    pub doctype_pattern: String,
    pub field: String,
    pub fetch_from: String,
    pub fetch_if_empty: Option<bool>,
}

/// One managed file: `repo` is the source of truth, `path` its place on `host`.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ParityFile {
    pub host: String,
    pub path: String,
    pub repo: String,
}

/// `[parity]` table: managed-file parity and engine version parity checked by `stenio verify-host`.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ParityConfig {
    #[serde(default)]
    pub files: Vec<ParityFile>,
    /// Container on the host that runs the engine (`docker exec <name> stenio --version`).
    pub stenio_container: Option<String>,
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
    pub frappe: Option<FrappeConfig>,
    pub parity: Option<ParityConfig>,
}

impl SteniocheckConfig {
    pub fn load_from_file(toml_path: &Path) -> Self {
        fs::read_to_string(toml_path)
            .ok()
            .and_then(|c| toml::from_str::<SteniocheckConfig>(&c).ok())
            .unwrap_or_default()
    }

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
