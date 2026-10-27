# Post-merge security audit cycle

This prototype models the workflow from the conversation: **merge first, audit the accumulated changes afterward**. A repository has an audited commit checkpoint. When the tracked branch advances, its new commits are automatically *unaudited*. Each security pass reviews the whole range since that checkpoint and records the model, token usage, and findings. Fixes can land as more commits. After a pass reports no findings at the current tip, a person explicitly marks that tip audited. The next merge makes it unaudited again.

## Install

Clone this repository into the root of the Git repository you want to audit:

```sh
git clone https://github.com/altanapps/security-audit-cycle.git security-audit-cycle
mkdir -p .claude/skills/security-audit-cycle
cp security-audit-cycle/.claude/skills/security-audit-cycle/SKILL.md .claude/skills/security-audit-cycle/SKILL.md
```

Alternatively, clone it elsewhere and pass `--repo /path/to/target-repo` to each `cycle.py` command. If you use the Claude Code skill, keep the CLI at `security-audit-cycle/cycle.py` in the target repository as shown above.

This is an experimental local CLI and skill, not a hosted GitHub integration. Its audit state stays in the target repository's Git directory and is not shared or enforced by GitHub.

```text
Audited at A → merge PRs B and C → Unaudited (A..C)
           → security pass v12: findings, model, tokens → still Unaudited
           → fix D → security pass v13: no findings → mark D Audited
           → merge E → Unaudited (D..E)
```

## Try it

Requires Python 3.9+, Git, Claude Code CLI, and `ANTHROPIC_API_KEY`. The measured pass uses [Claude Code non-interactive JSON output](https://code.claude.com/docs/en/headless) and `--bare`; Anthropic documents that bare mode does not use subscription login. Run `audit` in a separate terminal outside an active Claude Code session.

Choose a commit that was **already reviewed** as the initial checkpoint. This command records your assertion; it does not perform a baseline audit:

```sh
python3 security-audit-cycle/cycle.py init --ref main --audited-commit <known-reviewed-sha>
python3 security-audit-cycle/cycle.py status
```

After several PRs have merged into `main`:

```sh
python3 security-audit-cycle/cycle.py audit --label v12 --model sonnet
python3 security-audit-cycle/cycle.py status
```

The status view is intentionally compact:

```text
Security audit state: UNAUDITED
Audited checkpoint: a1b2c3d4
Unaudited commits: 3
  Merge PR #12
  Merge PR #13
  Fix security finding
  pass v12: claude-sonnet-…; 18,400 tokens; 1 finding
  pass v13: claude-sonnet-…; 21,700 tokens; 0 findings
Measured tokens this cycle: 40,100
```

The audit command prints a run JSON path under the repository's Git directory. Review the findings in that file. If there are findings, commit fixes to the tracked branch and run another pass over the **entire accumulated range**. When the latest pass reports zero findings at the current tip:

```sh
python3 security-audit-cycle/cycle.py mark-audited --run /path/printed/by/latest/audit.json
python3 security-audit-cycle/cycle.py status
```

`mark-audited` rejects a stale, failed, or finding-bearing pass. If an earlier pass found issues at the same commit, a later zero-finding pass cannot close the cycle until a fix commit lands. A new commit after marking audited automatically changes the status back to unaudited. `status --json` provides structured data for a future GitHub-style UI.

## What is recorded

Every pass has its own JSON record: checkpoint and reviewed tip, diff hash, model IDs reported by Claude, input/cache/output token counts, findings, limitations, and pass status. Failed passes are kept; if the CLI did not report usage, the ledger says **unknown** rather than zero. The cycle total sums measured tokens across all passes, including passes before fixes.

State and run records live in `<git-dir>/security-audit-cycle/`. `status` lists commits since the checkpoint; a commit may correspond to a merged PR, but the script does not claim to identify PRs reliably. A hosted version would connect merge events to PR identities and publish the same state and token ledger in a shared repository view.

The audit is security-only and diff-only. A zero-finding pass means the model did not report a finding in that pass; it is not proof that the code is secure. The script refuses binary and over-200-KB diffs rather than presenting a partial audit as complete.
