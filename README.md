# falcon-cloud-risk-remediation-skill

A **Claude Code agent skill** for fetching and remediating CrowdStrike Falcon cloud security risks using the Falcon CSPM API.

## What this is

This is raw material for an AI agent to re-implement in its own unique environment — not a drop-in tool. It is designed to be read and adapted by a Claude Code agent (or similar LLM-based agent), which will tailor it to the specific cloud accounts, credentials, and CLI tooling available in that environment.

**Do not use as-is.** An agent should:
1. Read `SKILL.md` to understand the workflow intent
2. Adapt the credential setup (`setup_credentials.py`) to match the local secret store
3. Adapt the risk fetcher (`fetch_risks.py`) to match the target CID and region
4. Wire the execution steps to the cloud CLI tools available in that environment

## What it does

1. **Fetches** open cloud risks from `CloudSecurity.combined_cloud_risks()` — filtered by severity, provider, and FQL
2. **Presents** a dry-run preview per risk, including the attack narrative and exact CLI commands extracted from Falcon's pre-built remediation instructions
3. **Executes** — after explicit per-risk confirmation — via `aws`, `az`, or `gcloud` CLI
4. **Validates** using the validation commands embedded in each risk's `remediation_plan`
5. **Reports** results to a markdown file

## Files

| File | Purpose |
|------|---------|
| `SKILL.md` | Claude-driven workflow — the agent reads this at runtime |
| `setup_credentials.py` | Credential setup for macOS Keychain, Windows Credential Manager, Linux env vars |
| `fetch_risks.py` | Fetch risks from Falcon API with FQL filtering |
| `remediation-reports/` | Output directory for remediation reports (gitignored) |

## Prerequisites

- Python 3 + `crowdstrike-falconpy` (`pip install crowdstrike-falconpy`)
- CrowdStrike API client with **CSPM (read)** and **Cloud Security (read)** scopes
- Cloud CLI(s) for the providers you want to remediate: `aws`, `az`, `gcloud`
- macOS Keychain, Windows Credential Manager, or environment variables for credential storage

## Adapting for your environment

Key things an agent will need to change:

- **Default profile name** — `talon_1` is the example; replace with your CID profile name
- **Region** — defaults to `us-1`; change for `us-2`, `eu-1`, or GovCloud
- **Execution path** — if you have cloud skills (/aws, /azure, /gcp) with guardrails, wire Phase 3 through them; otherwise direct CLI is used
- **Report output path** — currently writes to the skill directory; redirect to your workspace

## Credential storage format

Credentials are stored by profile name (account) with these service keys:

| Service key | Content |
|-------------|---------|
| `falcon-client-id` | CrowdStrike API client ID |
| `falcon-client-secret` | CrowdStrike API client secret |
| `falcon-cloud-region` | Region string (e.g. `us-1`) |

## License

MIT
