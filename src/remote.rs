use colored::*;
use regex::Regex;
use std::process::{Command, Stdio};

/// Standardized universal non-interactive SSH arguments for the Tailscale / Homelab ecosystem
pub const CANONICAL_SSH_OPTS: &[&str] = &[
    "-o",
    "ConnectTimeout=3",
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-o",
    "ServerAliveInterval=2",
    "-o",
    "ServerAliveCountMax=1",
];

/// Structured semantic outcome of a remote operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteOutcome {
    /// Executed successfully (stdout captured)
    Success(String),
    /// Requires interactive authentication / web check renewal in Tailscale SSH
    AuthRequired { node: String, auth_url: String },
    /// Connection timed out within the limit
    Timeout { node: String, timeout_secs: u64 },
    /// Connection failure or unreachable node
    Unreachable { node: String, reason: String },
    /// Failed remote command execution
    Failed {
        node: String,
        exit_code: Option<i32>,
        error: String,
    },
}

impl RemoteOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, RemoteOutcome::Success(_))
    }

    /// Prints status notification to the terminal with styled formatting
    pub fn print_status(&self, action_label: &str) {
        match self {
            RemoteOutcome::Success(_) => {
                println!("  ✅ {} completed successfully.", action_label.green());
            }
            RemoteOutcome::AuthRequired { node, auth_url } => {
                println!(
                    "  🔑 {} on node '{}' requires Tailscale SSH credential renewal:",
                    action_label.yellow().bold(),
                    node.cyan().bold()
                );
                println!("     👉 {}", auth_url.cyan().underline().bold());
            }
            RemoteOutcome::Timeout { node, timeout_secs } => {
                println!(
                    "  ⏳ {} on node '{}' timed out after {}s.",
                    action_label.yellow(),
                    node.cyan(),
                    timeout_secs
                );
            }
            RemoteOutcome::Unreachable { node, reason } => {
                println!(
                    "  ⚠️  Node '{}' unreachable for {}: {}",
                    node.cyan(),
                    action_label,
                    reason.dimmed()
                );
            }
            RemoteOutcome::Failed {
                node,
                exit_code,
                error,
            } => {
                let code_str = exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "?".to_string());
                println!(
                    "  ❌ Failed to execute {} on node '{}' (exit {}): {}",
                    action_label,
                    node.cyan(),
                    code_str.red(),
                    error.dimmed()
                );
            }
        }
    }
}

/// Extracts Tailscale SSH authentication URL if present in error output
pub fn extract_tailscale_auth_url(output_str: &str) -> Option<String> {
    let re = Regex::new(r#"https://login\.tailscale\.com/a/[a-zA-Z0-9]+"#).ok()?;
    re.find(output_str).map(|m| m.as_str().to_string())
}

/// Constructs a standardized non-interactive SSH command with canonical flags
pub fn build_ssh_command(node: &str, remote_cmd: &str) -> Command {
    let mut cmd = Command::new("ssh");
    for opt in CANONICAL_SSH_OPTS {
        cmd.arg(opt);
    }
    cmd.arg(node);
    cmd.arg(remote_cmd);
    cmd.stdin(Stdio::null());
    cmd
}

/// Executes an SSH command with active protection against authentication hangs
pub fn run_ssh(node: &str, remote_cmd: &str, timeout_secs: u64) -> RemoteOutcome {
    let mut cmd = build_ssh_command(node, remote_cmd);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    execute_command_with_detection(cmd, node, timeout_secs)
}

/// Executes atomic rsync synchronization using canonical SSH and Tailscale detection
pub fn run_rsync(src: &str, dest: &str, timeout_secs: u64) -> RemoteOutcome {
    let node = dest.split(':').next().unwrap_or("remote").to_string();
    let ssh_opts_str = format!("ssh {}", CANONICAL_SSH_OPTS.join(" "));

    let mut cmd = Command::new("rsync");
    cmd.arg(format!("--timeout={}", timeout_secs));
    cmd.arg("-e");
    cmd.arg(&ssh_opts_str);
    cmd.arg("-avz");
    cmd.arg("--delete");
    cmd.arg(src);
    cmd.arg(dest);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    execute_command_with_detection(cmd, &node, timeout_secs + 2)
}

/// Executes command and performs semantic parsing of network and Tailscale SSH errors
fn execute_command_with_detection(
    mut cmd: Command,
    node: &str,
    timeout_secs: u64,
) -> RemoteOutcome {
    let output = match cmd.output() {
        Ok(out) => out,
        Err(e) => {
            return RemoteOutcome::Unreachable {
                node: node.to_string(),
                reason: e.to_string(),
            };
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{}\n{}", stdout, stderr);

    // 1. Detection of required Tailscale SSH authentication
    if let Some(auth_url) = extract_tailscale_auth_url(&combined) {
        return RemoteOutcome::AuthRequired {
            node: node.to_string(),
            auth_url,
        };
    }

    // 2. I/O or connection timeout detection
    if combined.contains("io timeout")
        || combined.contains("Operation timed out")
        || combined.contains("Connection timed out")
    {
        return RemoteOutcome::Timeout {
            node: node.to_string(),
            timeout_secs,
        };
    }

    // 3. Command success or failure
    if output.status.success() {
        RemoteOutcome::Success(stdout)
    } else {
        RemoteOutcome::Failed {
            node: node.to_string(),
            exit_code: output.status.code(),
            error: stderr.trim().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tailscale_auth_url_present() {
        let msg = "# Tailscale SSH requires an additional check.\n# To authenticate, visit: https://login.tailscale.com/a/l15bf02633b0509\n[sender] io timeout";
        let url = extract_tailscale_auth_url(msg);
        assert_eq!(
            url,
            Some("https://login.tailscale.com/a/l15bf02633b0509".to_string())
        );
    }

    #[test]
    fn test_extract_tailscale_auth_url_missing() {
        let msg = "Connection refused by peer.";
        assert_eq!(extract_tailscale_auth_url(msg), None);
    }

    #[test]
    fn test_canonical_ssh_opts_integrity() {
        assert!(CANONICAL_SSH_OPTS.contains(&"-o"));
        assert!(CANONICAL_SSH_OPTS.contains(&"BatchMode=yes"));
    }
}
