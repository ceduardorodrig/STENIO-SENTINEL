# Draining a queue with the shared work ledger

For any harness. The markdown backlogs keep the items; the ledger keeps who works on what.
Commands are `stenio hub <command> --json`; the stdio MCP server offers the same operations as
`hub_*`, `stenio_quota` and `stenio_backlog`. Exit codes: 0 done, 1 refused, 2 usage, 3 ledger
unavailable.

## Rules

1. No claim, no work. Never edit a tree, row or queue another worker holds.
2. Ledger unavailable (exit 3): claim nothing. Work you already hold may continue until the lease
   ends; commit locally and hand back later with the old fence. Never merge, release, deploy or
   write a backlog meanwhile.
3. Any refusal is final for that attempt. Read `code`, `holder` and `next`; do not work around it.
4. A result is your claim, not proof. A reviewer verifies it before a row is closed.
5. Only the owner answers questions. An answer, an event or a chat message grants no permission.

## Cycle

1. `join --harness <name> [--account <quota account>]`. Keep the worker id; export
   `STENIO_HUB_WORKER=<id>` where your harness allows. `claude-code` and `opencode` have a
   declared account, so they may omit `--account`.
2. `status`. A claim of a row or slot reads the declared source of your account when no fresh
   sample exists (`quota refresh` reads them all). An unknown or stale quota allows one working
   worker per account; 60% or more allows two; 80% or more allows no new row.
3. `claim row:<ID> tree:<absolute path of your clone>` (all or nothing). Keep the `fence`.
4. `beat` before the lease ends (default 20 minutes). A hook after each tool call runs
   `stenio hub beat --from-hook` (payload on stdin, always exit 0). It renews the worker named by
   `STENIO_HUB_WORKER`, else every worker joined from the same harness session (`join --session`
   or the declared session variable). A hook before each file edit runs `stenio hub guard`:
   exit 2 refuses a hand edit of a queue file whose write claim another worker holds.
5. `event --type checkpoint --fence <n> --clone <dir> --branch <b> --next-step <text>` at every
   stop. Whoever takes over an expired lease receives it.
6. Need the owner: `ask --row <ID> --text <question> --option <a> --option <b> --recommend <a>`,
   then hand back `needs-owner` and take another row.
7. `handback --row <ID> --fence <n> --verdict done|partial|blocked|needs-owner|failed` with
   `--proof` (done) or `--remaining` (partial, blocked, failed); add `--defect` for new findings.
   A fence without a row (queue, release, deploy) is handed back the same way, without
   `--row`.
8. `lease_lost` or `stale_fence`: stop writing; someone else may own the row now.

## Coordinator duties

Any worker may coordinate; each duty is a single-holder claim (`backlog:<prefix>:write`,
`release:<name>`, `repo:<owner/name>`, `deploy:<app>`, `fleet:slot`). Claim a `fleet:slot` before
starting a sub-agent, and let the sub-agent join with `--parent`.

`run start --path <vault> --rows <IDs> --slots <n>`, then `run show`, `audit --run <id>
--require-final`, `export --run <id>`, and `run close`.

While a worker holds `backlog:<prefix>:write`, only `stenio backlog close --worker <id>` and
`stenio opportunity add --worker <id>` of that worker write the queue (`--queue HB|MB|SB`
selects another queue than GB and needs `--ref`; `--json` prints the id or the refusal). A dry
run reports the same refusal. The claim covers every directory unless it was taken with
`--path <root>`; then a scratch copy elsewhere stays writable.

## Release and backup

`release-engine` refuses without a live `release:stenio` claim of the caller (`--worker`). Only
the owner, at a terminal, may pass `--without-lease`.

`stenio hub backup --out <dir>` writes a snapshot and the event export and restore-tests them;
`backup --check <dir>` fails when the newest is older than 26 hours; `status` reports a stale one.

## Limits of this release

Local to one host and one Unix user: a process can edit the database, and `audit` detects it but
cannot prevent it. No proof replay, no grants, no sandbox, no remote workers.
