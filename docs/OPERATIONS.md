# JARVIS Operations

## Validation

Run the full local validation stack:

```bash
bash scripts/validate.sh
```

The script compiles Python, runs Ruff, mypy, pytest, tool-contract checks,
offline evals, Bandit, and frontend lint/build/audit when `node_modules` is
installed.

## Secrets

Runtime settings still read environment variables, but API keys updated through
`/api/settings/update` are stored in the secure keyring backend. On macOS this
uses Keychain through the Python `keyring` package. Existing `.env` API keys are
honored for compatibility, but new API key writes are no longer persisted to
plain text.

## PIN Authorization

Tools marked `requires_authorization` (e.g. `trash_file`) need a PIN typed into
the local web UI. Telegram, iMessage and voice only post "This needs your PIN on
your Mac." and can never approve. Set or change the PIN from a terminal on the
Mac itself (refused over SSH or without a TTY):

```bash
python -m jarvis.core.authz set-pin
```

Only a salted scrypt hash is stored (in the Keychain via the secrets backend).
Three wrong PINs lock authorization for five minutes. With no PIN set, no UI
open, or a timeout, the tool is blocked.

## Traces And Audits

HTTP requests, background jobs, and tool executions are correlated with
`X-Trace-ID`. Trace spans are written to:

```text
data/logs/traces.jsonl
```

Tool execution audit records are written to:

```text
data/jarvis_security_audit.db
```

Set `JARVIS_TOOL_PERMISSION_MODE=enforce` to block tools that require explicit
confirmation when a tool call does not include `confirmed=true`. The default is
`audit`, which records classifications without disrupting current workflows.

## Background Jobs

Long-running chat work can be queued through:

```text
POST /jobs
GET /jobs
GET /jobs/{job_id}
POST /jobs/{job_id}/cancel
```

Jobs persist in `data/jarvis_jobs.db`, survive process restarts, and keep their
trace IDs for follow-up diagnostics.

## Install And Update

Fresh macOS install:

```bash
bash scripts/install_macos.sh
```

Build a Finder-launchable app bundle and DMG:

```bash
bash scripts/package_macos_app.sh
```

Install the generated app into `~/Applications`:

```bash
bash scripts/package_macos_app.sh --install-user
```

The app bundle is a lightweight launcher over this checkout. It opens Terminal
and runs `./start.sh full`, prompting to install dependencies if `.venv` or UI
`node_modules` are missing. Keeping the runtime outside the app bundle avoids
writing mutable data into `/Applications` and lets `scripts/update_jarvis.sh`
continue to update the git checkout cleanly.

Update an existing checkout:

```bash
bash scripts/update_jarvis.sh
```
