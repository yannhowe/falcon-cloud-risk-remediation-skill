---
name: remediate-cloud-risks
description: Fetch open cloud risks from Falcon CSPM and execute their pre-built remediations via AWS/Azure/GCP CLI, with dry-run preview and per-risk confirmation.
---

# remediate-cloud-risks

Fetches CrowdStrike cloud risks via the Falcon API and executes their
pre-built, asset-specific remediation steps using the appropriate cloud
CLI skill — after dry-run preview and explicit per-risk confirmation.

## When to Use

- "Remediate cloud risks"
- "Fix cloud misconfigs from Falcon"
- "Run Falcon cloud risk remediations"
- "Auto-fix critical/high cloud security findings"
- "Execute cloud risk remediation steps"
- "Fix the [specific rule name] risk in [account]"

## Credential Setup (First Time)

Before using this skill, API credentials must be stored in the OS
native secret store — never in plaintext files or environment variables.

### macOS (Keychain)

```bash
cd /Users/ykwan/claude/.claude/skills/remediate-cloud-risks
python3 setup_credentials.py --profile talon_1
```

This stores three entries under account `talon_1`:
- Service `falcon-client-id` → your CrowdStrike API client ID
- Service `falcon-client-secret` → your CrowdStrike API client secret
- Service `falcon-cloud-region` → e.g. `us-1`

Create your API client at: https://falcon.crowdstrike.com/api-clients-and-keys
Required scopes: **CSPM (read)**, **Cloud Security (read)**

To list stored profiles:
```bash
python3 setup_credentials.py --list
```

### Windows (Credential Manager)

```powershell
cd C:\path\to\skills\remediate-cloud-risks
python setup_credentials.py --profile talon_1
```

Stored as targets `falcon-client-id:talon_1`, `falcon-client-secret:talon_1`, `falcon-cloud-region:talon_1` in Windows Credential Manager.

Verify in Windows: Start → "Credential Manager" → Windows Credentials.

### Linux (Environment Variables)

No secret store — use environment variables per-session:
```bash
export FALCON_CLIENT_ID=<your-client-id>
export FALCON_CLIENT_SECRET=<your-client-secret>
export FALCON_REGION=us-1
```

### Verify Credentials

```bash
python3 fetch_risks.py --profile talon_1 --severity Critical --limit 1 --summary
```
Expected: one-row table. A 401 means bad credentials; a 403 means missing CSPM scope.

---

## Workflow

### Phase 1 — Fetch risks

Run `fetch_risks.py` to retrieve risks. Defaults to Critical+High severity, all providers, open status.

```bash
# Default: Critical+High, all providers
python3 .claude/skills/remediate-cloud-risks/fetch_risks.py \
  --profile talon_1 --output /tmp/risks.json

# Specific provider or severity
python3 .claude/skills/remediate-cloud-risks/fetch_risks.py \
  --profile talon_1 --severity Critical --provider gcp --output /tmp/risks.json

# Specific account
python3 .claude/skills/remediate-cloud-risks/fetch_risks.py \
  --profile talon_1 --filter "account_name:'my-account'" --output /tmp/risks.json
```

Read the resulting JSON and extract the `risks` array.

### Phase 2 — Select and interpret each risk

For each risk in the list:

1. **Identify the CLI tool** by checking `provider` field:
   - `AWS` → use `/aws` skill (aws CLI)
   - `Azure` → use `/azure` skill (az CLI)
   - `GCP` → use `/gcp` skill (gcloud CLI)

2. **Find the CLI-executable remediation** by scanning `risk_factors`:
   For each entry in `risk_factors[].remediation[]`, look for `title` values like:
   - `"gcloud CLI"`, `"AWS CLI"`, `"Azure CLI"` — **these have executable commands**
   - `"Google Cloud console"`, `"Azure portal"`, `"AWS Console"` — skip (UI steps)
   - `"General"` — skip (generic advice)

3. **Read the risk summary for context:**
   - `risk_summary.narrative` — attack scenario
   - `remediation_plan.steps[]` — prioritized steps with `estimated_time`, `prerequisites`, `validations`

4. **Generate dry-run preview:** For each CLI-executable remediation block, interpret the
   content and output the exact commands you would run (using the actual resource names,
   IDs, and regions from the risk record). Present this to the user as:

   ```
   ─────────────────────────────────────────────────────────
   RISK [1/N]: [rule_name]
   Severity:   [severity]
   Asset:      [asset_name] ([asset_type])
   Account:    [account_name] / [provider]
   Narrative:  [risk_summary.narrative — first sentence]

   DRY-RUN — commands that would be executed:

   Step 1: [remediation_plan.steps[0].title]
   Estimated time: [estimated_time]
   Prerequisites: [prerequisites as bullet list]

     $ [command 1]
     $ [command 2]

   Validation:
     $ [validations[0]]

   ─────────────────────────────────────────────────────────
   Execute this risk? [y/N/skip/quit]:
   ```

### Phase 3 — Execute on confirmation

For each risk the user confirms (`y`):

1. **Check for optional cloud skills** — before executing, check whether `/aws`, `/azure`, or `/gcp`
   skills are available (they provide SCP checks, scope enforcement, and guardrails).
   Announce which path will be used:

   ```
   ℹ️  Execution path for this risk:
       Provider: GCP
       • /gcp skill available → routing through it (guardrails active)
       — OR —
       • /gcp skill not found → executing gcloud commands directly (no guardrails)
         Tip: install the /gcp skill for scope enforcement and cost guardrails.
   ```

2. **Execute commands** using whichever path is available:
   - **If the matching cloud skill exists** (`/gcp`, `/aws`, `/azure`): invoke it — it enforces
     project/region scope, blocked-command lists, and requires confirmation on destructive ops.
   - **If no cloud skill is present**: run the `gcloud` / `aws` / `az` command directly via Bash,
     but still confirm destructive operations (delete, remove, revoke) with the user before running.

3. After executing each step, run the validation commands from `remediation_plan.steps[].validations[]`
   and confirm the output matches the expected state.

4. Record result: `success`, `failed`, or `skipped`.

### Phase 4 — Report

After all risks are processed, write a markdown report to:
`/Users/ykwan/claude/.claude/skills/remediate-cloud-risks/remediation-reports/remediation-YYYY-MM-DD-HH-MM.md`

Report structure:
```markdown
# Cloud Risk Remediation Report
Date: YYYY-MM-DD HH:MM
Profile: talon_1  |  Filters: severity=Critical,High

## Summary
- Risks reviewed: N
- Remediations executed: N
- Successful: N
- Failed: N
- Skipped: N

## Results

### ✓ [rule_name] — [asset_name]
- Provider: GCP | Account: [account_name]
- Steps executed: [list]
- Validation: passed

### ✗ [rule_name] — [asset_name]
- Error: [what went wrong]
- Manual steps: [paste the console-based remediation as fallback]
```

---

## Safety Rules

- **Always dry-run first** — never execute commands without showing the full command list to the user first
- **Per-risk confirmation** — ask `[y/N/skip/quit]` before each risk, never batch-execute
- **Respect cloud skill guardrails** — the `/gcp`, `/aws`, `/azure` skills have their own safety checks; route through them, never bypass
- **If a risk has no CLI remediation** (only console UI steps), skip execution and note in the report with the manual steps pasted in
- **Skip risks with `status: Resolved`** — `fetch_risks.py` already filters for Open, but double-check before executing
- **Prerequisites gate execution** — if `remediation_plan.steps[].prerequisites` lists permissions or maintenance windows you can't verify, warn the user before proceeding

---

## Common FQL Filters

```bash
# Only AWS, Critical
--severity Critical --provider aws

# Specific account
--filter "account_name:'my-account'"

# Identity-related risks only
--filter "service_category:'Identity'"

# Specific rule
--filter "rule_name:'Unused identity'"

# Storage risks, High+Critical
--severity Critical,High --filter "service_category:'Storage'"
```

---

## Files

| File | Purpose |
|------|---------|
| `SKILL.md` | This file — skill definition and workflow |
| `setup_credentials.py` | Credential setup for macOS/Windows/Linux |
| `fetch_risks.py` | Fetch risks from Falcon API |
| `remediation-reports/` | Output reports (gitignored) |

## Dependencies

This skill has **no hard dependencies** — fetch and dry-run work standalone. The following are optional enhancements:

| Skill | Provider | What it adds | Without it |
|-------|----------|-------------|------------|
| `/aws` | AWS | SCP policy checks, blocked-command list, region scope | Direct `aws` CLI — user must have CLI configured (`aws configure`) |
| `/azure` | Azure | Resource group scope enforcement, GPU/cost guardrails | Direct `az` CLI — user must be logged in (`az login`) |
| `/gcp` | GCP | Project scope, machine-type guardrails, Artifact Registry helpers | Direct `gcloud` CLI — user must be authenticated (`gcloud auth login`) |
| `/falcon-api` | — | Shared auth reference and FalconPy patterns | Auth is self-contained in `fetch_risks.py` / `setup_credentials.py` |

At the start of any execution phase, announce which optional skills are present and which are absent.

## Related Skills (all optional)

- `/falcon-api` — shared FalconPy auth reference; auth is self-contained here but useful for troubleshooting
- `/gcp` — GCP CLI with project scope + guardrails; if absent, `gcloud` is used directly
- `/aws` — AWS CLI with SCP checks; if absent, `aws` is used directly
- `/azure` — Azure CLI with scope enforcement; if absent, `az` is used directly

Last Updated: 2026-09-11
