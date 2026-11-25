"""Scope the private Lido VEX repository to the repository being built.

Trivy ignores the Lido fields `whitelist_repositories` and `whitelist_expires`, so a
statement read straight from lidofinance/vex would hide the CVE in every service.
After `trivy vex repo download`, this command rewrites the downloaded `internal`
repository in place: a `not_affected` / `fixed` statement stays only if the calling
repository is listed in `whitelist_repositories` and `whitelist_expires` (inclusive,
UTC) has not passed. Other statuses stay. Documents left empty are removed from the
index so Trivy never sees them. Malformed data fails the step (fail closed).
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Mapping

from harbor_helper.common import WorkflowError, required

SUPPRESSING = {"not_affected", "fixed"}
REPOSITORY = "internal"


def _allowed(statement: dict, repository: str, today: date) -> tuple[bool, str]:
    if statement.get("status") not in SUPPRESSING:
        return True, "not a suppression"
    repositories = statement.get("whitelist_repositories")
    expires = statement.get("whitelist_expires")
    if not isinstance(repositories, list) or not isinstance(expires, str):
        return False, "no whitelist scope"
    try:
        expiry = date.fromisoformat(expires)
    except ValueError:
        raise WorkflowError(f"Invalid whitelist_expires '{expires}' in Lido VEX") from None
    if repository not in repositories:
        return False, "other repository"
    if expiry < today:
        return False, f"expired {expires}"
    return True, f"allowed until {expires}"


def scope_documents(root: Path, repository: str, today: date) -> list[tuple[str, str, str, bool, str]]:
    """Filter `root` (…/repositories/internal/0.1) in place; return one row per statement."""
    rows: list[tuple[str, str, str, bool, str]] = []
    index_path = root / "index.json"
    try:
        index = json.loads(index_path.read_text())
        packages = index["packages"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise WorkflowError("Lido VEX index.json is missing or invalid") from error
    kept = []
    for entry in packages:
        path = (root / entry["location"]).resolve()
        if not path.is_relative_to(root.resolve()) or path.is_symlink():
            raise WorkflowError("Lido VEX document location escapes the repository")
        try:
            document = json.loads(path.read_text())
            statements = document["statements"]
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise WorkflowError(f"Lido VEX document {entry['location']} is invalid") from error
        selected = []
        for statement in statements:
            keep, reason = _allowed(statement, repository, today)
            name = statement.get("vulnerability", {}).get("name", "?")
            rows.append((name, entry["id"], statement.get("status", "?"), keep, reason))
            if keep:
                selected.append(statement)
        if selected:
            document["statements"] = selected
            path.write_text(json.dumps(document))
            kept.append(entry)
        else:
            path.unlink()
    index["packages"] = kept
    index_path.write_text(json.dumps(index))
    return rows


def scope_vex(environment: Mapping[str, str]) -> dict[str, str]:
    repository = required(environment, "GITHUB_REPOSITORY")
    root = Path(required(environment, "VEX_CACHE_DIR")) / "vex" / "repositories" / REPOSITORY / "0.1"
    today = datetime.now(timezone.utc).date()
    rows = scope_documents(root, repository, today)
    kept = sum(row[3] for row in rows)
    with Path(required(environment, "GITHUB_STEP_SUMMARY")).open("a") as summary:
        summary.write(f"### Lido VEX scope for `{repository}` ({today})\n\n")
        summary.write("| Vulnerability | Package | Status | Applied | Reason |\n|---|---|---|---|---|\n")
        for name, package, status, keep, reason in rows:
            summary.write(f"| {name} | `{package}` | {status} | {'✅ yes' if keep else '❌ no'} | {reason} |\n")
        summary.write(f"\n{kept} of {len(rows)} Lido VEX statements apply to this repository.\n\n")
    for name, package, status, keep, reason in rows:
        print(f"{'apply' if keep else 'skip '}  {name}  {package}  {status}  ({reason})")
    print(f"Lido VEX: {kept} of {len(rows)} statements apply to {repository}")
    return {}
