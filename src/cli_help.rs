//! `stenio <subcommand> --help` (GB-387): the first line names the subcommand, and the two that
//! are rewritten into other arguments print their own text instead of another command's.

/// Subcommands dispatched in `main` (the secret gates declare theirs in `secrets_suite`).
pub const SUBCOMMANDS: &[&str] = &[
    "backlog",
    "binary-parity",
    "compare-engines",
    "config",
    "drift",
    "frappe-drift",
    "gate",
    "hostops",
    "hub",
    "language",
    "opportunity",
    "pre-release",
    "preflight",
    "release-engine",
    "secrets-guard",
    "sweep",
    "verify-host",
    "verify-release",
];

const BACKLOG: &str = "Read the queues of the vault.

Usage: stenio backlog [--path <vault>] [--search <term>]
       stenio backlog --next-id <HB|SB|MB|GB>
       stenio backlog close <ids> --note <proof> [--state resolved|discarded] [--dry-run]

`stenio opportunity add` writes a new row; `stenio backlog close --help` lists its options.";

const PREFLIGHT: &str = "The static part of the release gate of a Frappe app repository.

Usage: stenio preflight --repo <dir> [options]

Same as `stenio pre-release --static-only`; `stenio pre-release --help` lists the options.";

pub fn names() -> impl Iterator<Item = &'static str> {
    SUBCOMMANDS
        .iter()
        .copied()
        .chain(crate::secrets_suite::command_names())
}

/// For a help request of a subcommand: prints its name and, for a rewritten one, its help.
/// Returns the exit code when nothing else has to run.
pub fn announce(argv: &[String]) -> Option<i32> {
    let sub = argv.get(1)?;
    if !matches!(argv.get(2).map(String::as_str), Some("--help" | "-h")) || argv.len() != 3 {
        return None;
    }
    if !names().any(|n| n == sub) {
        return None;
    }
    println!("stenio {sub}");
    let own = match sub.as_str() {
        "backlog" => BACKLOG,
        "preflight" => PREFLIGHT,
        _ => return None,
    };
    println!("{own}");
    Some(0)
}
