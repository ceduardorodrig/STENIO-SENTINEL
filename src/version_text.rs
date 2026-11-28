//! GB-391: one version, `Cargo.toml`. A title or heading that states another one is stale.

/// Lines that claim to name the engine's current version and name another.
pub fn stale(text: &str, current: &str) -> Vec<String> {
    text.lines()
        .filter(|l| l.starts_with('#') || l.contains("Rust Engine"))
        .filter(|l| l.contains("StenioSentinel") || l.contains("Key Capabilities"))
        .filter(|l| {
            l.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
                .filter_map(|w| w.strip_prefix('v'))
                .filter(|v| v.contains('.') && v.starts_with(|c: char| c.is_ascii_digit()))
                .any(|v| v.trim_end_matches('.') != current)
        })
        .map(str::to_string)
        .collect()
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let current = env!("CARGO_PKG_VERSION");
    vec![(
        "version text: a stale version in a title is found, the current one is not".to_string(),
        stale("# StenioSentinel (v4.14.0) engine", current).len() == 1
            && stale("## Key Capabilities (v4.18.0 Superpowers)", current).len() == 1
            && stale(&format!("# StenioSentinel v{current}"), current).is_empty()
            && stale("- Since StenioSentinel v4.1.0 something", current).is_empty(),
    )]
}

#[cfg(test)]
mod tests {
    #[test]
    fn fixtures() {
        crate::testkit::assert_cases(super::self_test_cases());
    }

    /// A test, not a self-test case: the container build copies the sources without the pages.
    #[test]
    fn readme_and_agents_state_no_stale_version() {
        let current = env!("CARGO_PKG_VERSION");
        for page in [include_str!("../README.md"), include_str!("../AGENTS.md")] {
            assert_eq!(super::stale(page, current), Vec::<String>::new());
        }
    }
}
