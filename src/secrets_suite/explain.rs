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
    RuleExplanation {
        id: "SECRETS-STORE-DRIFT",
        name: "Secret Stores Disagree",
        severity: "ERROR",
        tag: "sec",
        summary: "`stenio secrets-drift --store S [--master M] [--mirror HOST=F] [--consumer L=F] [--require KEY] [--decrypt]` fails naming key and host when a key is missing on one side, a mirror's sops_lastmodified is older than the store, a value differs between comparable files, or a consumer needs a key the store lacks. Silent and exit 0 when consistent; exit 2 when a file cannot be read.",
        rationale: "A provider key lived only in two local files while both stores lacked it, and a host mirror was three weeks old; it surfaced while debugging an outage (2026-11-06).",
        bad_example: "stenio secrets-drift --store vault.enc.env --mirror kavure=old.enc.env\n# FAIL mirror kavure: stale ...",
        good_example: "stenio secrets-drift --store vault.enc.env --master master.env --mirror kavure=copy.enc.env --decrypt",
        remediation: "Add the key with the store script, re-encrypt and copy the store to the host; never edit a mirror by hand.",
    },
];
