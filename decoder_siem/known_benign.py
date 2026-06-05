from __future__ import annotations

from urllib.parse import urlparse

from decoder_siem.models import Artifact, ArtifactType

TRUSTED_DOMAINS: frozenset[str] = frozenset(
    {
        "google.com",
        "google.it",
        "googlemail.com",
        "gmail.com",
        "youtube.com",
        "gstatic.com",
        "googleusercontent.com",
        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "office365.com",
        "outlook.com",
        "outlook.it",
        "hotmail.com",
        "hotmail.it",
        "live.com",
        "live.it",
        "msn.com",
        "apple.com",
        "icloud.com",
        "me.com",
        "yahoo.com",
        "yahoo.it",
        "aol.com",
        "facebook.com",
        "meta.com",
        "amazon.com",
        "amazonaws.com",
        "proton.me",
        "protonmail.com",
        "zoho.com",
        "mimecast.com",
        "proofpoint.com",
        "barracuda.com",
        "messagelabs.com",
    }
)

def _normalize_domain(domain: str) -> str:
    return domain.lower().strip().strip(".")


def is_trusted_domain(domain: str) -> bool:
    d = _normalize_domain(domain)
    if not d:
        return False
    if d in TRUSTED_DOMAINS:
        return True
    for trusted in TRUSTED_DOMAINS:
        if d.endswith(f".{trusted}"):
            return True
    return False


def host_from_url(url: str) -> str | None:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname
        return host.lower() if host else None
    except Exception:  # noqa: BLE001
        return None


def is_known_benign_artifact(artifact: Artifact) -> bool:
    if artifact.type == ArtifactType.DOMAIN:
        return is_trusted_domain(artifact.normalized_value)
    if artifact.type == ArtifactType.URL:
        host = host_from_url(artifact.normalized_value)
        return bool(host and is_trusted_domain(host))
    if artifact.type == ArtifactType.EMAIL_ADDRESS:
        if "@" in artifact.normalized_value:
            domain = artifact.normalized_value.rsplit("@", 1)[-1]
            return is_trusted_domain(domain)
    return False
