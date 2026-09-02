#!/usr/bin/env python3
"""Verify GPG signatures on pull-request commits."""

import os
import sys
import tempfile
from pathlib import Path

from config import GITHUB_WEB_FLOW_PRIMARY_FINGERPRINTS, REPOSITORIES
from src.errors import VerificationError
from src.git import resolve_commit_sha
from src.gpg import find_group_public_key_files, import_public_keys
from src.verify_commit_signatures import verify_introduced_commit_signatures


def main() -> None:
    """Read GitHub Action inputs and execute PR commit verification."""
    base_sha = resolve_commit_sha(os.environ.get("BASE_SHA", ""), "BASE_SHA")
    head_sha = resolve_commit_sha(os.environ.get("HEAD_SHA", ""), "HEAD_SHA")
    key_root = Path(__file__).with_name("trusted-gpg-keys")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not repository or repository.startswith("/") or repository.endswith("/") or repository.count("/") > 1:
        raise VerificationError(f"invalid GITHUB_REPOSITORY value: {repository!r}")
    policy = REPOSITORIES.get(repository) or REPOSITORIES.get(repository.rsplit("/", 1)[-1])
    if policy is None:
        raise VerificationError(f"no signer policy is configured for repository {repository!r}")

    with tempfile.TemporaryDirectory(prefix="commit-signature-verification-") as temporary:
        public_key_files = find_group_public_key_files(key_root, policy.signers)
        github_key_file = Path(__file__).with_name("github-web-flow.asc")
        _, allowed_primary_keys = import_public_keys(public_key_files, Path(temporary) / "contributors")
        if allowed_primary_keys & GITHUB_WEB_FLOW_PRIMARY_FINGERPRINTS:
            raise VerificationError("GitHub web-flow keys must not be configured as contributor signers")
        gpg_env, all_primary_keys = import_public_keys(
            [*public_key_files, github_key_file], Path(temporary) / "gnupg"
        )
        if all_primary_keys != allowed_primary_keys | GITHUB_WEB_FLOW_PRIMARY_FINGERPRINTS:
            raise VerificationError(
                f"{github_key_file}: GitHub web-flow key fingerprints do not match the pinned policy"
            )
        verify_introduced_commit_signatures(base_sha, head_sha, gpg_env, allowed_primary_keys, policy.dry)


if __name__ == "__main__":
    try:
        main()
    except VerificationError as error:
        print(f"::error::{error}", file=sys.stderr)
        raise SystemExit(1)
