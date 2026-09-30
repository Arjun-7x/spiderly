"""
SPIDERLY - Validation & safety helpers.

Everything that touches user-supplied input (target host, port ranges,
scan config) is validated here BEFORE it ever reaches the scanner or a
subprocess. No shell commands are ever built from raw user input.
"""
import ipaddress
import re
from typing import List, Tuple

from app.core.config import settings

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class ValidationError(Exception):
    pass


def validate_target(target: str) -> str:
    """Accept a valid IPv4/IPv6 address or a syntactically valid hostname.
    Rejects anything containing shell metacharacters, spaces, or control chars.
    """
    target = (target or "").strip()
    if not target or len(target) > 253:
        raise ValidationError("Target must be a non-empty string under 253 characters.")

    if any(c in target for c in [";", "|", "&", "$", "`", ">", "<", "\n", "\r", " ", "'", '"']):
        raise ValidationError("Target contains invalid characters.")

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    if HOSTNAME_RE.match(target):
        return target

    raise ValidationError("Target is not a valid IP address or hostname.")


PORT_CHUNK_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def parse_port_spec(spec: str) -> List[int]:
    """Parse a comma-separated list of ports and/or ranges, e.g. '22,80,1000-1010'.
    Returns a sorted, de-duplicated list of ports. Enforces sane bounds.
    Malformed input always raises ValidationError (never a bare ValueError).
    """
    if not spec or not spec.strip():
        raise ValidationError("Port specification cannot be empty.")

    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        m = PORT_CHUNK_RE.match(chunk)
        if not m:
            raise ValidationError(f"Invalid port or range: '{chunk}'.")
        start = int(m.group(1))
        end = int(m.group(2)) if m.group(2) else start
        if start > end:
            start, end = end, start
        _validate_port_bounds(start)
        _validate_port_bounds(end)
        ports.update(range(start, end + 1))
        if len(ports) > settings.MAX_PORT_RANGE_SIZE:
            raise ValidationError(
                f"Requested {len(ports)}+ ports exceeds the safety limit of "
                f"{settings.MAX_PORT_RANGE_SIZE}. Narrow your range."
            )

    if not ports:
        raise ValidationError("No valid ports found in specification.")

    return sorted(ports)


def _validate_port_bounds(p: int) -> None:
    if p < 1 or p > 65535:
        raise ValidationError(f"Port {p} is out of the valid range 1-65535.")


def validate_scan_mode(mode: str) -> str:
    if mode not in ("quick", "standard", "custom"):
        raise ValidationError("Scan mode must be one of: quick, standard, custom.")
    return mode


def check_target_policy(address: str) -> None:
    """Enforce the target policy on a *resolved* IP address.

    Always refuses link-local (which covers the cloud metadata endpoint),
    multicast, unspecified and reserved addresses. Optionally refuses
    private/loopback ranges and/or enforces a network allowlist.
    """
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        raise ValidationError(f"'{address}' is not a resolvable IP address.")

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped

    if addr.is_unspecified or addr.is_multicast or addr.is_link_local or addr.is_reserved:
        raise ValidationError(f"Target {addr} is in a blocked address range.")

    if not settings.ALLOW_PRIVATE_TARGETS and (addr.is_private or addr.is_loopback):
        raise ValidationError(f"Target {addr} is private/loopback and SPIDERLY_ALLOW_PRIVATE=false.")

    nets = settings.ALLOWED_TARGET_NETWORKS
    if nets and not any(addr in n for n in nets if n.version == addr.version):
        raise ValidationError(f"Target {addr} is not in SPIDERLY_ALLOWED_TARGETS.")
