//! `BLOCKLIST-DOMAIN-VERIFY` (GB-259): every hostname of a claimed blocklist is resolved.

use std::process::Command;

use super::{case, opt, unreadable, verdict};
use crate::explain::RuleExplanation;

pub const RULE_ID: &str = "BLOCKLIST-DOMAIN-VERIFY";

pub const EXPLAIN: RuleExplanation = RuleExplanation {
    id: RULE_ID,
    name: "Blocklist Entry Does Not Resolve",
    severity: "ERROR",
    tag: "homelab",
    summary: "`stenio hostops domains --file LIST [--resolver 1.1.1.1]` resolves every hostname of the list (one per line, hosts-file and `||name^` forms accepted) with dig and prints resolves / NODATA / NXDOMAIN with the CNAME target. Exit 1 when any entry is NXDOMAIN.",
    rationale: "GB-259: 26 LG hostnames were checked by hand to separate real endpoints from blocklist folklore (informative.lge.com is NXDOMAIN).",
    bad_example: "informative.lge.com   # NXDOMAIN",
    good_example: "a list where every name answers",
    remediation: "Drop the NXDOMAIN entries or cite where the name was observed.",
};

/// Hostname of one list line, if any.
pub fn hostname(line: &str) -> Option<String> {
    let line = line.split(['#', '!']).next().unwrap_or("").trim();
    let word = line.split_whitespace().last()?;
    let word = word.trim_start_matches("||").trim_end_matches(['^', '.']);
    let valid = word.contains('.')
        && !word.starts_with('-')
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
        && word.chars().any(|c| c.is_ascii_alphabetic());
    valid.then(|| word.to_ascii_lowercase())
}

/// (status, CNAME chain, has address) from `dig +noall +comments +answer`.
pub fn parse_dig(out: &str) -> (String, Vec<String>, bool) {
    let mut status = String::from("NOANSWER");
    let (mut cnames, mut address) = (Vec::new(), false);
    for l in out.lines() {
        if let Some(rest) = l.split("status: ").nth(1) {
            status = rest.split(',').next().unwrap_or("").to_string();
        }
        let f: Vec<&str> = l.split_whitespace().collect();
        if !l.starts_with(';') && f.len() >= 5 {
            match f[3] {
                "CNAME" => cnames.push(f[4].trim_end_matches('.').to_string()),
                "A" | "AAAA" => address = true,
                _ => {}
            }
        }
    }
    (status, cnames, address)
}

pub fn run_cli(args: &[String]) -> i32 {
    let Some(file) = opt(args, "--file") else {
        return unreadable(RULE_ID, "--file <list> is required");
    };
    let Ok(list) = std::fs::read_to_string(&file) else {
        return unreadable(RULE_ID, format!("cannot read {file}"));
    };
    let resolver = opt(args, "--resolver").unwrap_or_else(|| "1.1.1.1".to_string());
    if resolver.starts_with('-') || !crate::verify_release::safe(&resolver, ":") {
        return unreadable(RULE_ID, "unsafe --resolver");
    }
    let names: Vec<String> = list.lines().filter_map(hostname).collect();
    if names.is_empty() {
        return unreadable(RULE_ID, "no hostname in the list");
    }
    let mut dead = Vec::new();
    for name in &names {
        let mut c = Command::new("dig");
        c.args([
            &format!("@{resolver}"),
            name,
            "A",
            "+noall",
            "+comments",
            "+answer",
            "+time=3",
            "+tries=2",
        ]);
        let out = match crate::verify_release::spawn_with_timeout(
            c,
            std::time::Duration::from_secs(15),
        ) {
            Ok(o) if o.code == 0 => o.stdout,
            Ok(o) => return unreadable(RULE_ID, format!("dig exited {} for {name}", o.code)),
            Err(e) => return unreadable(RULE_ID, e),
        };
        let (status, cnames, address) = parse_dig(&out);
        let state = match (status.as_str(), address) {
            ("NOERROR", true) => "resolves",
            ("NOERROR", false) => "NODATA",
            (other, _) => other,
        };
        println!("{name}\t{state}\t{}", cnames.join(" -> "));
        if status == "NXDOMAIN" {
            dead.push(format!("{name} is NXDOMAIN"));
        } else if status != "NOERROR" {
            return unreadable(RULE_ID, format!("{name}: resolver answered {status}"));
        }
    }
    verdict(RULE_ID, &file, names.len(), &dead)
}

pub fn self_test_cases() -> Vec<(String, bool)> {
    let nx = ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n";
    let ok = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2\na.example.\t60\tIN\tCNAME\tb.example.\nb.example.\t60\tIN\tA\t192.0.2.1\n";
    vec![
        case(
            "domains: NXDOMAIN is recognised",
            parse_dig(nx).0 == "NXDOMAIN",
        ),
        case(
            "domains: CNAME target and address are read",
            parse_dig(ok) == ("NOERROR".into(), vec!["b.example".into()], true),
        ),
        case(
            "domains: list formats and comments",
            hostname("0.0.0.0 Ads.example.com # x") == Some("ads.example.com".into())
                && hostname("||t.example.com^") == Some("t.example.com".into())
                && hostname("# only a comment").is_none()
                && hostname("-x.example").is_none(),
        ),
    ]
}
