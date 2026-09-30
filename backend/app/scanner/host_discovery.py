"""
SPIDERLY - Host discovery.

Raw ICMP pings require elevated privileges on most systems, so SPIDERLY
uses a lightweight TCP-based reachability check instead: it attempts a
fast connect to a small set of very commonly open ports. If any of them
respond (open OR actively refused, both mean "there's a live host here"),
the host is considered reachable. This is a standard, safe technique used
by many userland recon tools when ICMP is unavailable or blocked.
"""
import asyncio
import ipaddress
import socket
from typing import Tuple

PROBE_PORTS = [80, 443, 22, 445, 3389]
PROBE_TIMEOUT = 1.0


class ResolutionError(Exception):
    pass


async def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address (IPv4 preferred). IP literals are
    returned unchanged. Raises ResolutionError if the name cannot be resolved,
    so the scan fails with a clear message instead of scanning nothing."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ResolutionError(f"Could not resolve '{target}': {exc.strerror or exc}") from exc
    if not infos:
        raise ResolutionError(f"Could not resolve '{target}'.")
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    return infos[0][4][0]


async def _probe(ip: str, port: int) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=PROBE_TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (ConnectionRefusedError,):
        # Refused still means something answered on that IP
        return True
    except Exception:
        return False


async def check_reachable(ip: str) -> bool:
    results = await asyncio.gather(*[_probe(ip, p) for p in PROBE_PORTS])
    return any(results)
