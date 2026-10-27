---
name: security-audit-cycle
description: Track post-merge security audit debt, inspect security pass token usage and findings, and close a reviewed checkpoint.
disable-model-invocation: true
argument-hint: "[status|audit|mark-audited]"
---

This workflow applies after PRs have merged into the tracked branch. Use `python3 security-audit-cycle/cycle.py status --json` to read the local audited/unaudited state and the current cycle's pass ledger. Explain pending commits, each pass's reported model and token spend, findings, and any unknown usage. Do not describe an unaudited state as insecure or an audited state as secure.

To start a security pass, give the user `python3 security-audit-cycle/cycle.py audit --label <pass-name> --model <model>` to run in a **separate terminal outside Claude Code**. Do not launch a nested Claude Code CLI process from this skill. The command reviews all accumulated changes since the last checkpoint, records a run JSON file, and leaves the state unaudited.

If a pass has findings, help review and fix them when asked. After fixes land, require a fresh pass over the full checkpoint-to-tip range. When the latest pass completed at the current tip with zero findings, `python3 security-audit-cycle/cycle.py mark-audited --run <latest-run-json>` can close the cycle. Only perform that explicit state change when the user asks to mark the checkpoint audited. A new merge makes the tracked branch unaudited automatically.

If no checkpoint exists, ask for a commit known to have been reviewed and use `init --ref <branch> --audited-commit <sha>`. Never assume that HEAD was previously audited.
