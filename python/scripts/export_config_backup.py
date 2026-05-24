"""Export ISE configuration to versioned JSON files for git-based backup.

Pulls all the config objects we care about (NADs, NDGs, identity groups,
endpoint groups, endpoints, dACLs, authZ profiles, TACACS profiles, TACACS
command sets, AD join points, all policy sets + their rules) and writes them
to backups/<timestamp>/ as one JSON file per resource type.

Then symlinks backups/latest -> backups/<timestamp> so 'make backup' always
produces a stable diff target.

Usage:
    uv run python -m scripts.export_config_backup
    uv run python -m scripts.export_config_backup --commit   # auto git-commit
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from ise_api import ISEClient

console = Console()

# Fields ISE returns in plaintext that must NEVER be committed. Replace with sentinel.
SECRET_FIELD_NAMES = {
    "radiusSharedSecret",
    "sharedSecret",
    "secondRadiusSharedSecret",
    "keyEncryptionKey",
    "messageAuthenticatorCodeKey",
    "password",
    "enablePassword",
    "snmpRoCommunity",
    "snmpRwCommunity",
}
REDACTED = "<REDACTED>"


def _redact(obj):
    """Recursively replace any value whose key matches SECRET_FIELD_NAMES."""
    if isinstance(obj, dict):
        return {k: (REDACTED if k in SECRET_FIELD_NAMES else _redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj

# ERS collection endpoints (paginated list -> per-resource detail).
ERS_RESOURCES = [
    "networkdevice",
    "networkdevicegroup",
    "identitygroup",
    "endpointgroup",
    "endpoint",
    "downloadableacl",
    "authorizationprofile",
    "tacacsprofile",
    "tacacscommandsets",
    "activedirectory",
    "internaluser",
    "node",
    "allowedprotocols",
]

# OpenAPI policy endpoints — pull policy-sets, then their authN/authZ/exception rules.
OPENAPI_POLICY_KINDS = [
    "network-access",
    "device-admin",
]


def _export_ers(c: ISEClient, out_dir: Path) -> None:
    for resource in ERS_RESOURCES:
        items: list[dict] = []
        try:
            for stub in c.ers_paginate(resource):
                # Fetch full detail for each
                rid = stub.get("id")
                if not rid:
                    items.append(stub)
                    continue
                r = c.get(f"/ers/config/{resource}/{rid}")
                if r.status_code == 200:
                    items.append(r.json())
                else:
                    items.append({"_partial": True, **stub})
        except Exception as e:  # noqa: BLE001
            console.print(f"  [yellow]{resource}: {e}[/]")
            items = [{"_error": str(e)}]

        items = _redact(items)
        (out_dir / f"ers_{resource}.json").write_text(json.dumps(items, indent=2, sort_keys=True))
        console.print(f"  ers/{resource:25} [green]{len(items)} item(s)[/]")


def _export_policy(c: ISEClient, out_dir: Path) -> None:
    for kind in OPENAPI_POLICY_KINDS:
        base = f"/api/v1/policy/{kind}/policy-set"
        try:
            r = c.get(base)
            r.raise_for_status()
            policy_sets = r.json().get("response", [])
        except Exception as e:  # noqa: BLE001
            console.print(f"  [yellow]{kind} policy-sets: {e}[/]")
            continue

        enriched: list[dict] = []
        for ps in policy_sets:
            ps_id = ps["id"]
            entry: dict = {"policy_set": ps, "authentication": [], "authorization": [], "exception": []}
            for sub in ("authentication", "authorization", "exception"):
                try:
                    rr = c.get(f"{base}/{ps_id}/{sub}")
                    if rr.status_code == 200:
                        entry[sub] = rr.json().get("response", [])
                except Exception as e:  # noqa: BLE001
                    entry[sub] = [{"_error": str(e)}]
            enriched.append(entry)

        enriched = _redact(enriched)
        (out_dir / f"policy_{kind.replace('-', '_')}.json").write_text(
            json.dumps(enriched, indent=2, sort_keys=True)
        )
        console.print(f"  policy/{kind:25} [green]{len(enriched)} policy set(s)[/]")


def _update_latest_symlink(backup_root: Path, this_run: Path) -> None:
    latest = backup_root / "latest"
    if latest.is_symlink() or latest.exists():
        latest.unlink()
    latest.symlink_to(this_run.name)  # relative symlink


def _git_commit_if_requested(repo_root: Path, ts: str) -> None:
    try:
        subprocess.run(["git", "add", "backups/"], cwd=repo_root, check=True)
        diff = subprocess.run(
            ["git", "diff", "--cached", "--quiet"],
            cwd=repo_root,
        )
        if diff.returncode == 0:
            console.print("[yellow]No config changes since last backup — skipping commit.[/]")
            return
        subprocess.run(
            ["git", "commit", "-m", f"ISE config snapshot {ts}"],
            cwd=repo_root,
            check=True,
        )
        console.print(f"[green]Committed snapshot {ts}[/]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]git commit failed:[/] {e}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--commit", action="store_true", help="auto git-commit after export")
    args = ap.parse_args(argv)

    repo_root = Path(__file__).resolve().parents[2]
    backup_root = repo_root / "backups"
    backup_root.mkdir(exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    out_dir = backup_root / ts
    out_dir.mkdir()

    console.print(f"[bold]Snapshotting ISE config -> {out_dir.relative_to(repo_root)}[/]")
    with ISEClient() as c:
        if not c.ping():
            console.print("[red]ISE unreachable. Aborting.[/]")
            return 1

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), transient=True) as p:
            t = p.add_task("Exporting ERS resources…", total=None)
            _export_ers(c, out_dir)
            p.update(t, description="Exporting policy sets…")
            _export_policy(c, out_dir)

    _update_latest_symlink(backup_root, out_dir)
    console.print(f"[green]Done.[/] latest -> {out_dir.name}")

    if args.commit:
        _git_commit_if_requested(repo_root, ts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
