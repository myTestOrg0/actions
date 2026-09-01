"""Repository signer groups."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RepositoryPolicy:
    """Signer groups authorized for one repository."""

    signers: tuple[str, ...]
    dry: bool = False


REPOSITORIES = {
    # Repositories currently enforced with the SecOps signer group.
    "myTestOrg0/2026-08-signing-verifier-tests": RepositoryPolicy(("secops",), dry=False),
}
