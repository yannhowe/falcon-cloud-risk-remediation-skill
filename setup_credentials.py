#!/usr/bin/env python3
"""
CrowdStrike credential setup — macOS Keychain or Windows Credential Manager.

Usage:
  python3 setup_credentials.py              # interactive, detect platform
  python3 setup_credentials.py --profile talon_1
  python3 setup_credentials.py --list       # show stored profiles
"""
import argparse
import getpass
import platform
import subprocess
import sys


def detect_platform():
    s = platform.system()
    if s == "Darwin":
        return "macos"
    elif s == "Windows":
        return "windows"
    else:
        return "linux"


# ── macOS Keychain ──────────────────────────────────────────────────────────

def macos_store(service, account, secret):
    """Store or update a keychain entry."""
    # Delete existing first (add fails if entry exists)
    subprocess.run(
        ["security", "delete-generic-password", "-s", service, "-a", account],
        capture_output=True
    )
    result = subprocess.run(
        ["security", "add-generic-password", "-s", service, "-a", account, "-w", secret],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"Keychain store failed: {result.stderr.strip()}")


def macos_get(service, account):
    result = subprocess.run(
        ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
        capture_output=True, text=True
    )
    return result.stdout.strip() if result.returncode == 0 else None


def macos_list_profiles():
    """List all profile names that have stored falcon-client-id entries."""
    result = subprocess.run(
        ["security", "dump-keychain"],
        capture_output=True, text=True
    )
    profiles = []
    current_account = None
    for line in result.stdout.splitlines():
        if '"acct"' in line and '<blob>' in line:
            # Extract value between = and end of line
            parts = line.split('=', 1)
            if len(parts) > 1:
                current_account = parts[1].strip().strip('"')
        if '"svce"' in line and "falcon-client-id" in line and current_account:
            profiles.append(current_account)
            current_account = None
    return profiles


# ── Windows Credential Manager ──────────────────────────────────────────────

def windows_store(service, account, secret):
    """Store credential using cmdkey."""
    target = f"{service}:{account}"
    result = subprocess.run(
        ["cmdkey", f"/add:{target}", f"/user:{account}", f"/pass:{secret}"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"cmdkey failed: {result.stderr.strip()}")


def windows_get(service, account):
    """Retrieve credential using PowerShell CredentialManager module."""
    target = f"{service}:{account}"
    ps_script = (
        f"$cred = cmdkey /list:{target}; "
        f"if ($cred -match 'Target') {{ "
        f"$raw = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR("
        f"(Get-StoredCredential -Target '{target}').Password); "
        f"[System.Runtime.InteropServices.Marshal]::PtrToStringAuto($raw) }}"
    )
    result = subprocess.run(
        ["powershell", "-Command", ps_script],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        if "Get-StoredCredential" in result.stderr or "not recognized" in result.stderr.lower():
            print("ERROR: Get-StoredCredential not found. Install with: Install-Module CredentialManager -Force")
        return None
    return result.stdout.strip() if result.stdout.strip() else None


def windows_list_profiles():
    result = subprocess.run(
        ["cmdkey", "/list"],
        capture_output=True, text=True
    )
    profiles = []
    for line in result.stdout.splitlines():
        if "falcon-client-id:" in line:
            parts = line.strip().split("falcon-client-id:")
            if len(parts) > 1:
                profiles.append(parts[1].strip())
    return profiles


# ── Linux fallback (env var hint) ───────────────────────────────────────────

def linux_hint(profile):
    print("\nLinux detected. No OS secret store used.")
    print("Recommended: set environment variables before running:")
    print(f"  export FALCON_CLIENT_ID=<your-client-id>")
    print(f"  export FALCON_CLIENT_SECRET=<your-client-secret>")
    print(f"  export FALCON_PROFILE={profile}")


# ── Main flow ────────────────────────────────────────────────────────────────

def get_credential(os_platform, service, account):
    if os_platform == "macos":
        return macos_get(service, account)
    elif os_platform == "windows":
        return windows_get(service, account)
    return None


def store_credential(os_platform, service, account, secret):
    if os_platform == "macos":
        macos_store(service, account, secret)
    elif os_platform == "windows":
        windows_store(service, account, secret)


def list_profiles(os_platform):
    if os_platform == "macos":
        return macos_list_profiles()
    elif os_platform == "windows":
        return windows_list_profiles()
    return []


def setup_profile(os_platform, profile):
    print(f"\nSetting up CrowdStrike API credentials for profile '{profile}'")
    print("Get your API client from: https://falcon.crowdstrike.com/api-clients-and-keys")
    print("Required scopes: CSPM (read), Cloud Security (read)\n")

    client_id = input("Client ID: ").strip()
    if not client_id:
        print("Aborted — no client ID entered.")
        sys.exit(1)

    client_secret = getpass.getpass("Client Secret: ").strip()
    if not client_secret:
        print("Aborted — no client secret entered.")
        sys.exit(1)

    region = input("Region [us-1]: ").strip() or "us-1"

    store_credential(os_platform, "falcon-client-id", profile, client_id)
    store_credential(os_platform, "falcon-client-secret", profile, client_secret)
    store_credential(os_platform, "falcon-cloud-region", profile, region)

    print(f"\n✓ Credentials stored for profile '{profile}' (region: {region})")
    print(f"  Service keys: falcon-client-id / falcon-client-secret / falcon-cloud-region")
    print(f"  Account: {profile}")
    print(f"\nVerify with: python3 fetch_risks.py --profile {profile} --limit 1")


def main():
    parser = argparse.ArgumentParser(description="Store CrowdStrike credentials in OS secret store")
    parser.add_argument("--profile", default="talon_1", help="Profile name (default: talon_1)")
    parser.add_argument("--list", action="store_true", help="List stored profiles")
    args = parser.parse_args()

    os_platform = detect_platform()
    print(f"Platform: {os_platform}")

    if os_platform == "linux":
        linux_hint(args.profile)
        return

    if args.list:
        profiles = list_profiles(os_platform)
        if profiles:
            print("Stored profiles:")
            for p in profiles:
                print(f"  {p}")
        else:
            print("No stored profiles found.")
        return

    setup_profile(os_platform, args.profile)


if __name__ == "__main__":
    main()
