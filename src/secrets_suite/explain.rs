//! `--explain` entries of the suite (chained after the engine's own registry).

use crate::explain::RuleExplanation;

pub static EXPLANATIONS: &[RuleExplanation] = &[
    RuleExplanation {
        id: "SEC-SOPS-STORE-RECIPIENTS",
        name: "SOPS Store Lost A Recipient",
        severity: "ERROR",
        tag: "sec",
        summary: "`mnemocine/secrets.enc.env` (or `secrets.enc.env` at the scanned root) must declare at least two distinct age recipients (scopes vault and homelab).",
        rationale: "The store was re-encrypted twice in one hour by concurrent agents (2026-11-06) and the only guard was a manual rg: `--age` on the command line silently drops the second host's key.",
        bad_example: "sops_age__list_0__map_recipient=age1...   # only one",
        good_example: "sops_age__list_0__map_recipient=age1...\nsops_age__list_1__map_recipient=age1...",
        remediation: "Restore every recipient with `sops updatekeys` using the repository .sops.yaml.",
    },
];
