"""Repository signer groups."""

from dataclasses import dataclass


# Public key source: https://github.com/web-flow.gpg
GITHUB_WEB_FLOW_PRIMARY_FINGERPRINTS = frozenset({
    "5DE3E0509C47EA3CF04A42D34AEE18F83AFDEB23",
    "968479A1AFF927E37D1A566BB5690EEEBB952194",
})


@dataclass(frozen=True)
class RepositoryPolicy:
    """Signer groups authorized for one repository."""

    signers: tuple[str, ...]
    dry: bool = False


REPOSITORIES = {
    # Repositories currently enforced with the SecOps signer group.
    "myTestOrg0/2026-08-signing-verifier-tests": RepositoryPolicy(("secops",), dry=True),
}
