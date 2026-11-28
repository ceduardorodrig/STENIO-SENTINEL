//! GB-387: every subcommand help names its subcommand, and the scope list comes from the code.

use std::process::Command;

type Fallible = Result<(), Box<dyn std::error::Error>>;

/// The quoted names that open a declared list of a source file.
fn declared(source: &str, from: &str, to: &str, tuple: bool) -> Vec<String> {
    let body = source
        .split_once(from)
        .and_then(|(_, rest)| rest.split_once(to))
        .map_or("", |(body, _)| body);
    body.lines()
        .filter_map(|l| {
            let l = l.trim();
            let l = if tuple { l.strip_prefix('(')? } else { l };
            Some(l.strip_prefix('"')?.split('"').next()?.to_string())
        })
        .collect()
}

fn help(args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let out = Command::new(env!("CARGO_BIN_EXE_stenio"))
        .args(args)
        .output()?;
    assert!(out.status.success(), "{args:?}: {out:?}");
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn the_first_line_of_each_subcommand_help_names_it() -> Fallible {
    let mut names = declared(
        include_str!("../src/cli_help.rs"),
        "SUBCOMMANDS: &[&str] = &[",
        "];",
        false,
    );
    names.extend(declared(
        include_str!("../src/secrets_suite/mod.rs"),
        "const COMMANDS: &[(&str, Command)] = &[",
        "];",
        true,
    ));
    assert!(names.len() >= 20, "lists not read: {names:?}");
    // Every dispatch arm of `main` is declared.
    for arm in include_str!("../src/main.rs").split("Some(\"").skip(1) {
        if let Some((name, rest)) = arm.split_once('"')
            && rest.starts_with(") => std::process::exit")
        {
            assert!(names.iter().any(|n| n == name), "{name} is not declared");
        }
    }
    for name in &names {
        let text = help(&[name, "--help"])?;
        let first = text.lines().next().unwrap_or("");
        assert!(
            first.contains(name.as_str()),
            "{name}: first line `{first}`"
        );
    }
    assert!(help(&["backlog", "--help"])?.contains("stenio backlog --next-id"));
    assert!(help(&["preflight", "--help"])?.contains("stenio preflight --repo"));
    Ok(())
}

#[test]
fn the_scope_help_lists_every_accepted_scope() -> Fallible {
    let scopes = declared(
        include_str!("../src/selectors.rs"),
        "pub const SCOPES: &[&str] = &[",
        "];",
        false,
    );
    assert!(scopes.iter().any(|s| s == "frappe"), "{scopes:?}");
    let text = help(&["--help"])?;
    let line = text
        .lines()
        .find(|l| l.contains("--scope <SCOPE>"))
        .unwrap_or("");
    for scope in &scopes {
        assert!(line.contains(scope.as_str()), "{scope} missing: {line}");
    }
    Ok(())
}

#[test]
fn the_binary_passes_its_own_subcommand_parity() -> Fallible {
    let own = env!("CARGO_BIN_EXE_stenio");
    let out = help(&["binary-parity", "--installed", own, "--built", own])?;
    assert!(out.contains("binary-parity: 0 finding(s)"), "{out}");
    Ok(())
}
