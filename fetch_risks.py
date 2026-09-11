#!/usr/bin/env python3
"""
Fetch open cloud risks from CrowdStrike Falcon API.

Usage:
  python3 fetch_risks.py                               # Critical+High, all providers
  python3 fetch_risks.py --severity Critical           # only Critical
  python3 fetch_risks.py --provider aws                # only AWS
  python3 fetch_risks.py --profile sa-demo             # different CID
  python3 fetch_risks.py --limit 20 --output risks.json
  python3 fetch_risks.py --filter "account_name:'my-account'"
"""
import argparse
import json
import platform
import subprocess
import sys


def get_credential(profile, service):
    os_name = platform.system()
    if os_name == "Darwin":
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", profile, "-w"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
    elif os_name == "Windows":
        target = f"{service}:{profile}"
        ps = f"(Get-StoredCredential -Target '{target}').Password | ConvertFrom-SecureString -AsPlainText"
        result = subprocess.run(
            ["powershell", "-Command", ps],
            capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        if "Get-StoredCredential" in result.stderr:
            print("ERROR: Get-StoredCredential not found. Install with: Install-Module CredentialManager -Force",
                  file=sys.stderr)
    # Linux fallback: environment variables
    import os
    env_map = {
        "falcon-client-id": "FALCON_CLIENT_ID",
        "falcon-client-secret": "FALCON_CLIENT_SECRET",
        "falcon-cloud-region": "FALCON_REGION",
    }
    return os.environ.get(env_map.get(service, ""), None)


def build_fql_filter(severity, provider, extra_filter):
    parts = []
    if severity:
        sevs = [f"severity:'{s.strip()}'" for s in severity.split(",")]
        parts.append("+".join(f"({s})" for s in sevs) if len(sevs) > 1 else sevs[0])
    if provider:
        parts.append(f"cloud_provider:'{provider.upper()}'")
    parts.append("status:'Open'")
    if extra_filter:
        parts.append(extra_filter)
    return "+".join(parts)


def fetch_risks(profile, severity, provider, limit, extra_filter, offset=0):
    try:
        from falconpy import CloudSecurity
    except ImportError:
        print("ERROR: falconpy not installed. Run: pip install crowdstrike-falconpy", file=sys.stderr)
        sys.exit(1)

    client_id = get_credential(profile, "falcon-client-id")
    client_secret = get_credential(profile, "falcon-client-secret")
    region = get_credential(profile, "falcon-cloud-region") or "us-1"

    if not client_id or not client_secret:
        print(
            f"ERROR: No credentials found for profile '{profile}'.\n"
            f"Run: python3 setup_credentials.py --profile {profile}",
            file=sys.stderr
        )
        sys.exit(1)

    base_url_map = {
        "us-1": "https://api.crowdstrike.com",
        "us-2": "https://api.us-2.crowdstrike.com",
        "eu-1": "https://api.eu-1.crowdstrike.com",
        "gov": "https://api.laggar.gcw.crowdstrike.com",
    }
    base_url = base_url_map.get(region, "https://api.crowdstrike.com")

    cs = CloudSecurity(client_id=client_id, client_secret=client_secret,
                       base_url=base_url, pythonic=True)

    fql = build_fql_filter(severity, provider, extra_filter)
    params = {"filter": fql, "offset": offset} if fql else {"offset": offset}

    response = cs.combined_cloud_risks(limit=limit, parameters=params)
    body = response.full_return["body"]

    if response.status_code != 200:
        print(f"ERROR {response.status_code}: {body.get('errors', [])}", file=sys.stderr)
        sys.exit(1)

    return body


def main():
    parser = argparse.ArgumentParser(description="Fetch CrowdStrike cloud risks")
    parser.add_argument("--profile", default="talon_1")
    parser.add_argument("--severity", default="Critical,High",
                        help="Comma-separated severities (default: Critical,High)")
    parser.add_argument("--provider", help="Cloud provider: aws, azure, gcp")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--filter", dest="extra_filter", help="Extra FQL filter")
    parser.add_argument("--output", help="Write JSON to file instead of stdout")
    parser.add_argument("--summary", action="store_true", help="Print summary table, no full JSON")
    args = parser.parse_args()

    body = fetch_risks(args.profile, args.severity, args.provider,
                       args.limit, args.extra_filter)

    meta = body.get("meta", {})
    pagination = meta.get("pagination", {})
    resources = body.get("resources", [])

    if args.summary:
        total = pagination.get("total", len(resources))
        print(f"Total matching risks: {total} | Returned: {len(resources)}\n")
        print(f"{'Severity':<12} {'Rule':<55} {'Account':<22} {'Provider':<8} {'Service'}")
        print("-" * 120)
        for r in resources:
            print(
                f"{r.get('severity','?'):<12} "
                f"{r.get('rule_name','?')[:54]:<55} "
                f"{r.get('account_name', r.get('account_id','?'))[:21]:<22} "
                f"{r.get('provider','?'):<8} "
                f"{r.get('service_category','?')}"
            )
        return

    output = {
        "meta": {
            "total": pagination.get("total", 0),
            "returned": len(resources),
            "profile": args.profile,
            "filters": {
                "severity": args.severity,
                "provider": args.provider,
                "extra": args.extra_filter,
            }
        },
        "risks": resources
    }

    json_str = json.dumps(output, indent=2, default=str)

    if args.output:
        with open(args.output, "w") as f:
            f.write(json_str)
        print(f"Written {len(resources)} risks to {args.output}")
    else:
        print(json_str)


if __name__ == "__main__":
    main()
