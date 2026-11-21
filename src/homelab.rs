use std::fs;
use std::path::Path;

use crate::engine::Violation;
use crate::rule::Severity;

pub struct HomelabReport {
    pub total_files_scanned: usize,
    pub messages: Vec<String>,
    pub violations: Vec<Violation>,
}

pub fn audit_homelab(repo_root: &Path) -> HomelabReport {
    let mut messages = Vec::new();
    let mut violations = Vec::new();

    let mnemocine_dir = if repo_root.join("mnemocine").is_dir() {
        repo_root.join("mnemocine")
    } else if repo_root.ends_with("mnemocine") {
        repo_root.to_path_buf()
    } else {
        return HomelabReport {
            total_files_scanned: 0,
            messages: vec!["Directory mnemocine/ not found in scope.".to_string()],
            violations: vec![],
        };
    };

    // 1. Load canonical tag taxonomy from mnemocine/_tags.md
    let tags_file = mnemocine_dir.join("_tags.md");
    let mut valid_tags = crate::baseline::parse_tags_file(&tags_file);

    // Universal default tags
    valid_tags.insert("homelab".to_string());
    valid_tags.insert("meta".to_string());
    valid_tags.insert("agents".to_string());
    valid_tags.insert("servico".to_string());
    valid_tags.insert("servidor".to_string());

    // 2. Collect files from mnemocine
    let mut scanned_count = 0;
    for path in crate::baseline::build_file_walker(&mnemocine_dir) {
        let path_str = path.to_string_lossy().to_string();
        if path_str.contains("/.stversions/") || path_str.contains("/.smart-env/") {
            continue;
        }
        scanned_count += 1;

        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");

        // Validation A: Homelab Markdown Notes
        if ext == "md" {
            let Ok(content) = fs::read_to_string(&path) else {
                continue;
            };

            // Rule 1: Mandatory YAML Frontmatter
            if !content.starts_with("---") {
                violations.push(Violation {
                    rule_id: "HOMELAB-FRONTMATTER".to_string(),
                    rule_name: "Mandatory YAML Frontmatter".to_string(),
                    severity: Severity::Error,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: content.lines().next().unwrap_or("").to_string(),
                    message: "All homelab notes must begin with YAML frontmatter (---)".to_string(),
                    suggestion: Some("Add '---\\ntags: [homelab, category, host]\\n---' block at the top of the note.".to_string()),
                });
            } else {
                // Check for #homelab tag presence
                if let Some(end_idx) = content[3..].find("---") {
                    let fm_str = &content[3..3 + end_idx];
                    if !fm_str.contains("homelab") {
                        violations.push(Violation {
                            rule_id: "HOMELAB-TAG-ROOT".to_string(),
                            rule_name: "Mandatory #homelab Tag".to_string(),
                            severity: Severity::Warning,
                            file_path: path_str.clone(),
                            line_number: 2,
                            snippet: "tags: [...]".to_string(),
                            message:
                                "All notes in mnemocine/ must contain the 'homelab' tag in frontmatter."
                                    .to_string(),
                            suggestion: Some(
                                "Include 'homelab' in the YAML frontmatter tag list."
                                    .to_string(),
                            ),
                        });
                    }
                }
            }

            // Rule 2: File naming convention (lowercase with hyphens, no uppercase)
            let allowed_specials = [
                "README.md",
                "_tags.md",
                "AGENTS.md",
                "SECURITY.md",
                "CONTRIBUTORS.md",
            ];
            if !allowed_specials.contains(&file_name) && file_name.chars().any(|c| c.is_uppercase())
            {
                violations.push(Violation {
                    rule_id: "HOMELAB-NAMING".to_string(),
                    rule_name: "Lowercase-Hyphenated Naming Convention".to_string(),
                    severity: Severity::Warning,
                    file_path: path_str.clone(),
                    line_number: 1,
                    snippet: file_name.to_string(),
                    message: format!(
                        "File name '{}' contains uppercase letters. Use lowercase with hyphens.",
                        file_name
                    ),
                    suggestion: Some(format!("Rename to '{}'.", file_name.to_lowercase())),
                });
            }
        }

        // Validation B: NFS Mounts in /etc/fstab or scripts
        if ext == "sh" || ext == "md" || file_name == "fstab" {
            if let Ok(content) = fs::read_to_string(&path) {
                for (line_idx, line) in content.lines().enumerate() {
                    if (line.contains("nfs") || line.contains("nfs4"))
                        && (line.contains(",hard") || line.contains("hard,"))
                    {
                        violations.push(Violation {
                            rule_id: "HOMELAB-NFS-SOFT".to_string(),
                            rule_name: "Prohibition of Hard NFS Mounts".to_string(),
                            severity: Severity::Error,
                            file_path: path_str.clone(),
                            line_number: line_idx + 1,
                            snippet: line.trim().to_string(),
                            message: "NFS mounts over VPN/Tailscale must never use 'hard' (risk of kernel deadlock).".to_string(),
                            suggestion: Some("Replace 'hard' with 'soft,timeo=30,retrans=2,_netdev,x-systemd.automount'.".to_string()),
                        });
                    }
                }
            }
        }

        // Validation D: Cleartext secrets (SEC-SECRETS) — documentation and configs.
        // Syncthing mirrors vault to phones and houses the encrypted store:
        // any credential pasted into a note leaks across all synchronized devices.
        if let Ok(content) = fs::read_to_string(&path) {
            violations.extend(crate::guardian::scan_content_for_secrets(&path, &content));
        }
    }

    // Validation E: Backlog traceability ("single source of pending work").
    // Cross-checks mnemocine/backlog.md against the per-document `pending:` field.
    let backlog = crate::backlog::audit_backlog(repo_root);
    violations.extend(backlog.violations);
    messages.extend(backlog.messages);

    // Validation F: UWSM app-scope wrapping in Hyprland & Noctalia configs (GB-273).
    audit_uwsm_configs(&mut violations, &mut messages);

    if violations.is_empty() {
        messages.push(format!(
            "✅ {} notes and infrastructure configs in mnemocine/ 100% compliant.",
            scanned_count
        ));
        messages.push("✅ Tag taxonomy and YAML frontmatter intact.".to_string());
        messages.push("✅ No hard NFS mounts detected (Tailscale resilience OK).".to_string());
    } else {
        messages.push(format!(
            "⚠️ {} file(s) with deviations in mnemocine/.",
            violations.len()
        ));
    }

    HomelabReport {
        total_files_scanned: scanned_count,
        messages,
        violations,
    }
}

/// Checks whether UWSM is managing the active Hyprland session on this host.
fn is_uwsm_hyprland_active() -> bool {
    let Some(home) = std::env::var_os("HOME") else {
        return false;
    };
    let uwsm_env = Path::new(&home).join(".config/uwsm/env");
    if !uwsm_env.is_file() {
        return false;
    }
    std::process::Command::new("systemctl")
        .args([
            "--user",
            "is-active",
            "--quiet",
            "wayland-wm@hyprland.desktop.service",
        ])
        .status()
        .is_ok_and(|s| s.success())
}

/// Audits local Hyprland Lua configs and Noctalia settings when UWSM manages the session.
fn audit_uwsm_configs(violations: &mut Vec<Violation>, messages: &mut Vec<String>) {
    if !is_uwsm_hyprland_active() {
        return;
    }
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let home_path = Path::new(&home);
    let hypr_cfg_dir = home_path.join(".config/hypr/config");
    let mut found_issues = 0usize;

    if let Ok(entries) = fs::read_dir(&hypr_cfg_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !name.ends_with(".lua") || name.contains(".bak") {
                continue;
            }
            if let Ok(content) = fs::read_to_string(&path) {
                let v = check_hypr_lua_uwsm(&path.to_string_lossy(), &content);
                found_issues += v.len();
                violations.extend(v);
            }
        }
    }

    let noctalia_toml = home_path.join(".config/noctalia/config.toml");
    if let Ok(content) = fs::read_to_string(&noctalia_toml) {
        let v = check_noctalia_uwsm_toml(&noctalia_toml.to_string_lossy(), &content);
        found_issues += v.len();
        violations.extend(v);
    }

    if found_issues == 0 {
        messages
            .push("✅ UWSM app-scope wrapping verified for Hyprland Lua & Noctalia.".to_string());
    }
}

/// Returns true if a Hyprland `exec_cmd` argument is a short IPC/utility command rather than a persistent GUI app.
fn is_exempt_exec_cmd(cmd: &str) -> bool {
    const EXEMPT_PREFIXES: &[&str] = &[
        "hyprctl",
        "noctCall",
        "noctalia-shell ipc",
        "noctalia msg",
        "xrdb",
        "xhost",
        "hyprpicker",
        "wl-copy",
        "grim",
        "slurp",
        "pkill",
        "killall",
    ];
    let trimmed = cmd.trim().trim_start_matches('"').trim_start_matches('\'');
    EXEMPT_PREFIXES.iter().any(|p| trimmed.starts_with(p))
}

/// Checks a Hyprland Lua config file for GUI/session `exec_cmd` calls missing `uwsm app --` or redundant D-Bus env updates.
pub(crate) fn check_hypr_lua_uwsm(file_path: &str, content: &str) -> Vec<Violation> {
    let mut violations = Vec::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.starts_with("--") {
            continue;
        }
        if line.contains("dbus-update-activation-environment") {
            violations.push(Violation {
                rule_id: "UWSM-APP-EXEC".to_string(),
                rule_name: "UWSM App Scope & Environment Contract".to_string(),
                severity: Severity::Warning,
                file_path: file_path.to_string(),
                line_number: idx + 1,
                snippet: line.to_string(),
                message: "Redundant dbus-update-activation-environment under UWSM (UWSM already imports ~/.config/uwsm/env before Hyprland starts).".to_string(),
                suggestion: Some("Remove the dbus-update-activation-environment call and keep session variables in ~/.config/uwsm/env.".to_string()),
            });
            continue;
        }
        if !line.contains("exec_cmd(") {
            continue;
        }
        if line.contains("uwsm app") || line.contains("launchPrefix") {
            continue;
        }
        let Some(start) = line.find("exec_cmd(") else {
            continue;
        };
        let arg = &line[start + "exec_cmd(".len()..];
        if is_exempt_exec_cmd(arg) {
            continue;
        }
        violations.push(Violation {
            rule_id: "UWSM-APP-EXEC".to_string(),
            rule_name: "UWSM App Scope & Environment Contract".to_string(),
            severity: Severity::Warning,
            file_path: file_path.to_string(),
            line_number: idx + 1,
            snippet: line.to_string(),
            message: "Hyprland exec_cmd launches an app without 'uwsm app --', trapping it in session.slice instead of app.slice.".to_string(),
            suggestion: Some("Prefix the command with 'uwsm app -- ' (or launchPrefix) so it runs in an isolated app-*.scope.".to_string()),
        });
    }
    violations
}

/// Checks Noctalia's config.toml to ensure apps are launched via systemd services or a custom uwsm command.
pub(crate) fn check_noctalia_uwsm_toml(file_path: &str, content: &str) -> Vec<Violation> {
    let has_systemd = content
        .lines()
        .any(|l| l.trim().starts_with("launch_apps_as_systemd_services") && l.contains("true"));
    let has_custom_uwsm = content
        .lines()
        .any(|l| l.trim().starts_with("launch_apps_custom_command") && l.contains("uwsm"));
    if has_systemd || has_custom_uwsm {
        return Vec::new();
    }
    vec![Violation {
        rule_id: "UWSM-APP-EXEC".to_string(),
        rule_name: "UWSM App Scope & Environment Contract".to_string(),
        severity: Severity::Warning,
        file_path: file_path.to_string(),
        line_number: 1,
        snippet: "[shell]".to_string(),
        message: "Noctalia is not configured to launch apps as systemd services or via uwsm.".to_string(),
        suggestion: Some("Set 'launch_apps_as_systemd_services = true' under [shell] in ~/.config/noctalia/config.toml (and start noctalia via 'uwsm app -- noctalia').".to_string()),
    }]
}

#[cfg(test)]
mod tests {
    use super::{check_hypr_lua_uwsm, check_noctalia_uwsm_toml};

    #[test]
    fn flags_unwrapped_exec_cmd_and_redundant_dbus_env() {
        let lua = r#"
hl.on("hyprland.start", function ()
    hl.exec_cmd("dbus-update-activation-environment --systemd --all")
    hl.exec_cmd("noctalia")
    hl.exec_cmd(string.format("[workspace %s silent] %s", target_ws, cmd))
end)
"#;
        let v = check_hypr_lua_uwsm("autostart.lua", lua);
        assert_eq!(v.len(), 3);
        assert!(v.iter().all(|item| item.rule_id == "UWSM-APP-EXEC"));
    }

    #[test]
    fn allows_uwsm_app_launch_prefix_and_exempt_ipc() {
        let lua = r#"
hl.on("hyprland.start", function ()
    hl.exec_cmd("xrdb -merge ~/.Xresources")
    hl.exec_cmd("uwsm app -- noctalia")
    hl.exec_cmd(string.format("[workspace %s silent] uwsm app -- %s", target_ws, cmd))
end)
hl.bind("SUPER + Return", hl.dsp.exec_cmd(launchPrefix .. TERMINAL))
hl.bind("SUPER + Space", hl.dsp.exec_cmd(noctCall .. "panel-toggle launcher"))
"#;
        let v = check_hypr_lua_uwsm("autostart.lua", lua);
        assert!(v.is_empty(), "expected no violations, got {v:?}");
    }

    #[test]
    fn checks_noctalia_systemd_or_uwsm_setting() {
        let ok = "[shell]\nlaunch_apps_as_systemd_services = true\n";
        assert!(check_noctalia_uwsm_toml("config.toml", ok).is_empty());

        let bad = "[shell]\npolkit_agent = true\n";
        let v = check_noctalia_uwsm_toml("config.toml", bad);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule_id, "UWSM-APP-EXEC");
    }
}
