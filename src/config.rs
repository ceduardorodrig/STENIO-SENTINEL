use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

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

impl TopologyConfig {
    /// Every node any list declares.
    pub fn nodes(&self) -> Vec<String> {
        [
            &self.authorized_hub_nodes,
            &self.edge_nodes,
            &self.backend_nodes,
            &self.dev_gpu_nodes,
        ]
        .into_iter()
        .flatten()
        .flatten()
        .cloned()
        .collect()
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, serde::Serialize, Clone, Default)]
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

/// One `[[frappe.published_content]]` entry: a Single field whose source of truth is a packaged file.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct PublishedContent {
    pub doctype: String,
    pub field: String,
    pub file: String,
}

/// `[frappe]` table: static rules over a Frappe app tree (`--scope frappe`) and the
/// post-deploy checks of `stenio verify-release`. No project name lives in the engine.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct FrappeConfig {
    /// Documents `verify-release` compares between the live site and the running image (GB-149).
    pub published_content: Option<Vec<PublishedContent>>,
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

/// One `[[language.allow]]` entry: a gitignore glob where Portuguese is allowed, and why.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct LanguageAllow {
    pub path: String,
    #[serde(default)]
    pub reason: String,
}

/// `[language]` table: the central allowlist of a tree and the baseline holding its debt.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct LanguageConfig {
    pub allow: Option<Vec<LanguageAllow>>,
    pub baseline: Option<String>,
}

/// One `[[dependabot.exclude]]` entry: a lockfile directory that `DEPENDABOT-LOCKFILE-COVERAGE`
/// accepts without a Dependabot entry. The `reason` is mandatory; an empty one is a finding.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct DependabotExclude {
    /// Directory of the lockfile, relative to the repository root (`/`-rooted form accepted).
    pub directory: String,
    /// Ecosystem the exclusion applies to (`cargo`, `npm`); absent means every ecosystem.
    pub ecosystem: Option<String>,
    /// Why Dependabot must not cover this directory.
    #[serde(default)]
    pub reason: String,
    /// Rule the exclusion silences. Absent means `DEPENDABOT-LOCKFILE-COVERAGE`; the value
    /// `ignore-major` silences `DEPENDABOT-IGNORE-MAJOR` for the update entry whose
    /// `package-ecosystem` and `directory` match.
    pub rule: Option<String>,
}

/// `[dependabot]` table: sanctioned exclusions for `DEPENDABOT-LOCKFILE-COVERAGE`.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct DependabotConfig {
    pub exclude: Option<Vec<DependabotExclude>>,
}

/// One `[[ci.parity_exclude]]` entry: a workflow step that deliberately re-implements a Stenio
/// rule (`CI-STEP-STENIO-PARITY`). The `reason` is mandatory; an empty one silences nothing.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct CiParityExclude {
    /// Stenio rule id the inline step copies (e.g. `FRAPPE-LINK-TITLE`).
    pub rule: String,
    /// Substring of the step name; absent means every step.
    pub step: Option<String>,
    #[serde(default)]
    pub reason: String,
}

/// `[ci]` table: sanctioned exclusions for `CI-STEP-STENIO-PARITY`.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct CiConfig {
    pub parity_exclude: Option<Vec<CiParityExclude>>,
}

/// `[env_wiring]`: names `ENV-VAR-WIRED` accepts without a compose entry.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct EnvWiringConfig {
    pub ignore: Option<Vec<String>>,
}

/// `[stack_env]`: names a stack requires that something outside the repository consumes.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct StackEnvConfig {
    pub external: Option<Vec<String>>,
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
    pub language: Option<LanguageConfig>,
    pub parity: Option<ParityConfig>,
    pub dependabot: Option<DependabotConfig>,
    pub ci: Option<CiConfig>,
    pub env_wiring: Option<EnvWiringConfig>,
    pub stack_env: Option<StackEnvConfig>,
}

/// A configuration file that exists (or was named by the caller) but cannot be used. It is always
/// an error: silently falling back to the defaults switches rules off while the run stays green.
#[derive(Debug)]
pub struct ConfigError {
    pub path: PathBuf,
    pub cause: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "configuration error: {}: {}",
            self.path.display(),
            self.cause
        )
    }
}

impl std::error::Error for ConfigError {}

pub const FILE_NAME: &str = "steniocheck.toml";

impl SteniocheckConfig {
    /// Parses a configuration text and checks every custom rule (pattern, severity, id).
    pub fn parse(content: &str) -> Result<Self, String> {
        let config: SteniocheckConfig =
            toml::from_str(content).map_err(|e| e.to_string().trim_end().to_string())?;
        let mut seen = std::collections::HashSet::new();
        for rule in config.custom_rules.iter().flatten() {
            let id = &rule.id;
            if id.trim().is_empty() {
                return Err("custom rule with an empty id".to_string());
            }
            if !seen.insert(id.to_ascii_lowercase()) {
                return Err(format!("custom rule id '{id}' is declared twice"));
            }
            if let Err(e) = regex::Regex::new(&rule.pattern) {
                return Err(format!("custom rule '{id}': invalid pattern: {e}"));
            }
            if rule.extensions.is_empty() {
                return Err(format!(
                    "custom rule '{id}': empty `extensions` can never match a file"
                ));
            }
            if let Some(s) = rule.severity.as_deref() {
                if !["error", "warning", "warn"].contains(&s.to_ascii_lowercase().as_str()) {
                    return Err(format!(
                        "custom rule '{id}': unknown severity '{s}' (error, warning)"
                    ));
                }
            }
        }
        Ok(config)
    }

    /// Loads a file the caller named: a missing file is an error.
    pub fn load_from_file(toml_path: &Path) -> Result<Self, ConfigError> {
        let fail = |cause: String| ConfigError {
            path: toml_path.to_path_buf(),
            cause,
        };
        let content = fs::read_to_string(toml_path).map_err(|e| fail(e.to_string()))?;
        Self::parse(&content).map_err(fail)
    }

    /// Loads `<root>/steniocheck.toml`. Only a file that does not exist yields the defaults.
    pub fn load_from_dir(repo_root: &Path) -> Result<Self, ConfigError> {
        let toml_path = repo_root.join(FILE_NAME);
        match fs::symlink_metadata(&toml_path) {
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(Self::default())
            }
            _ => Self::load_from_file(&toml_path),
        }
    }

    /// The configuration of a run over `root` and the file it came from: the explicit file when
    /// one is named, else the nearest `steniocheck.toml` from `root` up to the repository root
    /// (outside a repository, up to the home directory, which is never read). Every such file on
    /// the way must parse, because directory rules read the nearest one.
    pub fn for_run(
        root: &Path,
        explicit: Option<&Path>,
    ) -> Result<(Self, Option<PathBuf>), ConfigError> {
        let absolute = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let mut nearest = None;
        for dir in absolute.ancestors() {
            if dir != absolute && (home.as_deref() == Some(dir) || dir.parent().is_none()) {
                break;
            }
            let config = Self::load_from_dir(dir)?;
            if nearest.is_none() && dir.join(FILE_NAME).is_file() {
                // Printed as the caller spelled the tree when it is the tree's own file.
                let file = if dir == absolute {
                    root.join(FILE_NAME)
                } else {
                    dir.join(FILE_NAME)
                };
                nearest = Some((config, file));
            }
            if dir.join(".git").exists() {
                break;
            }
        }
        match (explicit, nearest) {
            (Some(file), _) => Ok((Self::load_from_file(file)?, Some(file.to_path_buf()))),
            (None, Some((config, file))) => Ok((config, Some(file))),
            (None, None) => Ok((Self::default(), None)),
        }
    }
}
