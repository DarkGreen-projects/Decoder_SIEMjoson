from __future__ import annotations

import ipaddress
import re

SHA256_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")
SHA1_RE = re.compile(r"\b[A-Fa-f0-9]{40}\b")
MD5_RE = re.compile(r"\b[A-Fa-f0-9]{32}\b")
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
URL_RE = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)

# Hostname-like labels in incident text (not full domain validation)
HOSTNAME_RE = re.compile(r"\bHostname:\s*([^\r\n]+)", re.IGNORECASE)
HOST_IP_RE = re.compile(r"\bHost\s*IP:\s*([0-9.]+)", re.IGNORECASE)
PROCESS_SHA256_RE = re.compile(
    r"Process\s+SHA256:\s*([A-Fa-f0-9]{64})",
    re.IGNORECASE,
)
MALWARE_ID_RE = re.compile(r"Malware\s+ID:\s*([^\r\n]+)", re.IGNORECASE)


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def normalize_hash(value: str) -> str:
    return value.upper()


def normalize_ip(value: str) -> str:
    return value.strip()


def normalize_domain(value: str) -> str:
    return value.lower().rstrip(".")
