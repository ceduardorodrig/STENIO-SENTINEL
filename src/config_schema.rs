//! Keys of `steniocheck.toml` that do nothing. A key no rule reads is reported by name: an unknown
//! one is an error (a typo switches a setting off), a declared one the engine does not apply is a
//! warning.

use std::path::Path;

use crate::config::SteniocheckConfig;
use crate::engine::Violation;
use crate::rule::Severity;

pub const UNKNOWN_ID: &str = "SCAN-CONFIG-UNKNOWN-KEY";
pub const UNUSED_ID: &str = "SCAN-CONFIG-UNUSED-KEY";

/// Declared tables and keys that no code path applies. A trailing dot covers a whole table.
/// The test below fails when the sources start reading one of them.
pub const UNUSED: &[&str] = &[
    "general.name",
    "general.version",
    "general.min_laws_count",
    "general.agents_md",
    "security.prohibit_bare_sudo",
    "security.scan_hardcoded_secrets",
    "security.forbid_eval_exec",
    "architecture.prefer_rust_tools",
    "frontend.",
    "gpu.",
    "docs.",
    "dry.",
];

fn unused(path: &str) -> bool {
    UNUSED
        .iter()
        .any(|u| *u == path || (u.ends_with('.') && path.starts_with(u)))
}

/// Dotted paths of every key the file sets, array entries without their index.
fn keys(prefix: &str, value: &toml::Value, out: &mut Vec<String>) {
    match value {
        toml::Value::Table(table) => {
            for (name, inner) in table {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                out.push(path.clone());
                keys(&path, inner, out);
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                keys(prefix, item, out);
            }
        }
        _ => {}
    }
}

/// The line that names the last segment of a dotted path.
fn line_of(content: &str, path: &str) -> usize {
    let key = path.rsplit('.').next().unwrap_or(path);
    content
        .lines()
        .position(|l| {
            let t = l.trim_start();
            t.strip_prefix(key)
                .is_some_and(|rest| rest.trim_start().starts_with('='))
                || (t.starts_with('[') && t.trim_matches(['[', ']', ' ']).ends_with(key))
        })
        .map_or(1, |n| n + 1)
}

/// The paths the engine's own structures accept: what survives a parse into them and back.
fn known_paths(content: &str) -> Vec<String> {
    let mut ignored = Vec::new();
    let de = toml::Deserializer::new(content);
    let parsed: Result<SteniocheckConfig, _> =
        serde_ignored::deserialize(de, |path| ignored.push(path.to_string()));
    if parsed.is_err() {
        return Vec::new();
    }
    // `custom_rules.0.typo` and `security.typo` alike, without the indexes and `?` markers.
    ignored
        .iter()
        .map(|p| {
            p.split('.')
                .filter(|s| *s != "?" && s.parse::<usize>().is_err())
                .collect::<Vec<_>>()
                .join(".")
        })
        .collect()
}

/// Findings of one configuration file; nothing for a file that does not parse (that is a usage
/// error of its own).
pub fn diagnose_text(file: &str, content: &str) -> Vec<Violation> {
    let Ok(table) = content.parse::<toml::Table>() else {
        return Vec::new();
    };
    let unknown = known_paths(content);
    let mut set = Vec::new();
    keys("", &toml::Value::Table(table), &mut set);
    set.dedup();
    let finding = |id: &str, severity, path: &str, message: String| Violation {
        rule_id: id.to_string(),
        rule_name: "Configuration Key Without Effect".to_string(),
        severity,
        file_path: file.to_string(),
        line_number: line_of(content, path),
        snippet: path.to_string(),
        message,
        suggestion: Some("Remove the key, or fix its spelling.".to_string()),
    };
    let mut out: Vec<Violation> = unknown
        .iter()
        .map(|p| {
            finding(
                UNKNOWN_ID,
                Severity::Error,
                p,
                format!("`{p}` is not a key the engine knows: it changes nothing"),
            )
        })
        .collect();
    out.extend(set.iter().filter(|p| unused(p)).map(|p| {
        finding(
            UNUSED_ID,
            Severity::Warning,
            p,
            format!("`{p}` is accepted and not applied by the engine"),
        )
    }));
    out
}

pub fn diagnose(file: Option<&Path>) -> Vec<Violation> {
    let Some(file) = file else {
        return Vec::new();
    };
    std::fs::read_to_string(file)
        .map(|content| diagnose_text(&file.to_string_lossy(), &content))
        .unwrap_or_default()
}

/// What the engine uses for every key a file does not set. A test derives the key list from the
/// configuration structures, so a new key without an entry fails.
const DEFAULTS: &[(&str, &str)] = &[
    ("general.name", "unset"),
    ("general.version", "unset"),
    ("general.scope", "\"all\""),
    ("general.min_laws_count", "unset"),
    ("general.agents_md", "unset"),
    ("security.banned_python_packages", "@packages"),
    ("security.prohibit_bare_sudo", "unset"),
    ("security.scan_hardcoded_secrets", "unset"),
    ("security.forbid_eval_exec", "unset"),
    ("architecture.banned_modules", "@modules"),
    ("architecture.prefer_rust_tools", "unset"),
    ("frontend.enforce_zustand_shallow", "unset"),
    ("frontend.enforce_useeffect_cleanup", "unset"),
    ("frontend.enforce_audioworklet_samplerate", "unset"),
    ("frontend.enforce_wakelock_release", "unset"),
    ("frontend.enforce_m3_typography", "unset"),
    ("frontend.forbid_bare_dividers", "unset"),
    ("frontend.forbid_silent_console_errors", "unset"),
    ("frontend.forbid_debug_console_logs", "unset"),
    ("gpu.cache_dir", "unset"),
    ("gpu.active_whisper_model", "unset"),
    ("gpu.min_model_size_mb", "unset"),
    ("gpu.banned_bloat_dirs", "unset"),
    ("docs.enforce_doc_anchors", "unset"),
    ("docs.doc_anchor_prefix", "unset"),
    ("dry.enabled", "unset"),
    ("dry.min_lines", "unset"),
    ("dry.strict", "unset"),
    (
        "topology.authorized_hub_nodes",
        "[] (no list declared: INFRA-TOPOLOGY-COMPLIANCE judges nothing)",
    ),
    ("topology.edge_nodes", "[]"),
    ("topology.backend_nodes", "[]"),
    ("topology.dev_gpu_nodes", "[]"),
    ("custom_rules", "[] (no custom rule)"),
    (
        "frappe.published_content",
        "[] (no published document compared)",
    ),
    ("frappe.app", "inferred: the folder with hooks.py"),
    ("frappe.test_list_file", "unset"),
    ("frappe.test_list_anchor", "unset"),
    (
        "frappe.battery_file",
        "found: scripts/release-checks.sh next to or above the app",
    ),
    (
        "frappe.rehearsal_file",
        "found: scripts/rehearse.sh next to or above the app",
    ),
    (
        "frappe.release_file",
        "found: scripts/release.sh next to or above the app",
    ),
    ("frappe.sidebar_allowlist", "unset"),
    (
        "frappe.role_allowlist",
        "[] added to the built-in Frappe core roles",
    ),
    (
        "frappe.link_allowlist",
        "[] added to the built-in core targets",
    ),
    (
        "frappe.permission_markers",
        "[] added to the built-in markers",
    ),
    ("frappe.whitelist_external", "[]"),
    (
        "frappe.locale_file",
        "found: <package>/locale/*.po, else the bench layout",
    ),
    ("frappe.image", "unset"),
    ("frappe.site", "@site"),
    ("frappe.ping_url", "unset"),
    ("frappe.public_url", "unset"),
    (
        "frappe.rehearsal_project",
        "unset (the rehearsal check is skipped)",
    ),
    (
        "frappe.rehearsal_dir_glob",
        "unset (the rehearsal check is skipped)",
    ),
    (
        "frappe.scheduled_backup_glob",
        "unset (the scheduled dump check is skipped)",
    ),
    ("frappe.scheduled_backup_max_age_hours", "@backup_hours"),
    (
        "frappe.custom_rules_tag",
        "unset (pre-release skips the custom rules)",
    ),
    ("frappe.label_allowlist", "[]"),
    ("frappe.modified_allowlist", "[]"),
    ("frappe.fetch_parity", "[]"),
    ("language.allow", "[]"),
    ("language.baseline", "unset (no debt baseline)"),
    ("parity.files", "[]"),
    ("parity.stenio_container", "unset"),
    ("dependabot.exclude", "[]"),
    ("ci.parity_exclude", "[]"),
    ("env_wiring.ignore", "[]"),
    ("stack_env.external", "[]"),
];

fn default_text(entry: &str) -> String {
    let list = |items: &[&str]| format!("{items:?}");
    match entry {
        "@packages" => list(&crate::rule::DEFAULT_BANNED_PACKAGES),
        "@modules" => list(&crate::rule::DEFAULT_BANNED_MODULES),
        "@site" => format!("{:?}", crate::verify_release::DEFAULT_SITE),
        "@backup_hours" => {
            crate::verify_release::DEFAULT_SCHEDULED_BACKUP_MAX_AGE_HOURS.to_string()
        }
        other => other.to_string(),
    }
}

/// One line per key that `set` (dotted paths without array indexes) does not cover.
fn default_lines(set: &[String]) -> String {
    DEFAULTS
        .iter()
        .filter(|(key, _)| {
            !set.iter()
                .any(|s| s == key || s.strip_prefix(key).is_some_and(|r| r.starts_with('.')))
        })
        .map(|(key, value)| {
            let effect = if unused(key) {
                "not applied"
            } else {
                "applied"
            };
            format!(
                "{key} = {}  [{effect}; built-in default]\n",
                default_text(value)
            )
        })
        .collect()
}

/// `stenio config show`: every effective value and where it comes from.
pub fn show(root: &Path, explicit: Option<&Path>) -> Result<String, String> {
    let (_, file) = SteniocheckConfig::for_run(root, explicit).map_err(|e| e.to_string())?;
    let Some(file) = file else {
        return Ok(format!(
            "no steniocheck.toml applies: every value is the built-in default\n{}",
            default_lines(&[])
        ));
    };
    let content = std::fs::read_to_string(&file).map_err(|e| e.to_string())?;
    let table: toml::Table = content
        .parse()
        .map_err(|e: toml::de::Error| e.to_string())?;
    let unknown = known_paths(&content);
    let mut out = format!("file: {}\n", file.display());
    let mut set = Vec::new();
    let mut stack: Vec<(String, toml::Value)> = table.into_iter().rev().collect();
    while let Some((path, value)) = stack.pop() {
        match value {
            toml::Value::Table(inner) => {
                stack.extend(
                    inner
                        .into_iter()
                        .rev()
                        .map(|(k, v)| (format!("{path}.{k}"), v)),
                );
            }
            toml::Value::Array(items) if items.iter().all(toml::Value::is_table) => {
                stack.extend(
                    items
                        .into_iter()
                        .enumerate()
                        .rev()
                        .map(|(n, v)| (format!("{path}.{n}"), v)),
                );
            }
            value => {
                let plain: Vec<&str> = path
                    .split('.')
                    .filter(|s| s.parse::<usize>().is_err())
                    .collect();
                let plain = plain.join(".");
                set.push(plain.clone());
                let effect = if unknown.iter().any(|u| plain.starts_with(u.as_str())) {
                    "unknown"
                } else if unused(&plain) {
                    "not applied"
                } else {
                    "applied"
                };
                out.push_str(&format!(
                    "{path} = {value}  [{effect}; {}:{}]\n",
                    file.display(),
                    line_of(&content, &plain)
                ));
            }
        }
    }
    out.push_str(&default_lines(&set));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(dir: &Path, out: &mut String) {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                sources(&path, out);
            } else if !path.ends_with("config_schema.rs") && !path.ends_with("config.rs") {
                out.push_str(&std::fs::read_to_string(path).unwrap_or_default());
            }
        }
    }

    /// Fields of `name` in the configuration source, as `(field, type)`.
    fn fields(source: &str, name: &str) -> Vec<(String, String)> {
        let Some(body) = source
            .split_once(&format!("pub struct {name} {{"))
            .and_then(|(_, rest)| rest.split_once("\n}"))
        else {
            return Vec::new();
        };
        body.0
            .lines()
            .filter_map(|l| l.trim().strip_prefix("pub "))
            .filter_map(|l| l.trim_end_matches(',').split_once(": "))
            .map(|(f, t)| (f.to_string(), t.to_string()))
            .collect()
    }

    #[test]
    fn every_configuration_key_has_a_default_entry() {
        let source = include_str!("config.rs");
        let mut wanted = Vec::new();
        for (table, ty) in fields(source, "SteniocheckConfig") {
            let inner = ty.trim_start_matches("Option<").trim_end_matches('>');
            let keys = fields(source, inner);
            if keys.is_empty() {
                wanted.push(table);
            } else {
                wanted.extend(keys.into_iter().map(|(k, _)| format!("{table}.{k}")));
            }
        }
        let listed: Vec<&str> = DEFAULTS.iter().map(|d| d.0).collect();
        assert!(wanted.len() > 40, "structures not read: {wanted:?}");
        assert_eq!(wanted, listed);
    }

    #[test]
    fn show_names_a_source_for_every_value() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("stenio-show-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        std::fs::write(
            dir.join("steniocheck.toml"),
            "[general]\nscope = \"project\"\n",
        )
        .map_err(|e| e.to_string())?;
        let out = show(&dir, None);
        let _ = std::fs::remove_dir_all(&dir);
        let out = out?;
        let values: Vec<&str> = out.lines().skip(1).collect();
        assert_eq!(values.len(), DEFAULTS.len(), "{out}");
        assert!(
            values
                .iter()
                .all(|l| l.contains("built-in default]") || l.contains("steniocheck.toml:2]"))
        );
        assert!(out.contains("general.scope = \"project\"  [applied;"));
        assert!(out.contains("frappe.site = \"frontend\"  [applied; built-in default]"));
        Ok(())
    }

    #[test]
    fn no_key_declared_unused_is_read_by_the_sources() -> Result<(), regex::Error> {
        let mut text = String::new();
        sources(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut text,
        );
        for entry in UNUSED {
            let (table, key) = entry.split_once('.').unwrap_or((entry, ""));
            // A read goes through the table (`.dry`) or names the field (`.min_laws_count`).
            // `name` and `version` are fields of many structures: only a read of `general` counts.
            let pattern = if table == "general" && matches!(key, "name" | "version") {
                format!(r"general[^;]{{0,80}}\.\s*{key}\b")
            } else if key.is_empty() {
                format!(r"(config|cfg)\s*\.\s*{table}\b")
            } else {
                format!(r"\.\s*{key}\b")
            };
            assert!(
                !regex::Regex::new(&pattern)?.is_match(&text),
                "`{entry}` is read: remove it from UNUSED"
            );
        }
        Ok(())
    }

    #[test]
    fn unknown_and_unused_keys_are_named() {
        let found = diagnose_text(
            "steniocheck.toml",
            "[securty]\nx = 1\n[general]\nnope = 1\nname = \"n\"\nversion = \"1\"\nscope = \"project\"\n[dry]\nenabled = false\n[env_wiring]\nignore = []\n",
        );
        let named = |id: &str, key: &str| found.iter().any(|v| v.rule_id == id && v.snippet == key);
        assert!(named(UNKNOWN_ID, "securty"), "{found:?}");
        assert!(named(UNKNOWN_ID, "general.nope"), "{found:?}");
        assert!(named(UNUSED_ID, "dry.enabled"), "{found:?}");
        assert!(!found.iter().any(|v| v.snippet.contains("env_wiring")));
        assert!(named(UNUSED_ID, "general.name"), "{found:?}");
        assert!(named(UNUSED_ID, "general.version"), "{found:?}");
        assert!(!found.iter().any(|v| v.snippet == "general.scope"));
    }
}
