"""
SPIDERLY - Service identification.

Two layers of evidence:
1. A well-known port -> service name table (a guess, clearly labeled as such).
2. An actual banner grab: SPIDERLY connects to the open port and reads
   whatever the service sends first (or, for silent protocols, sends a
   harmless newline to elicit a response). This is real network I/O
   against the authorized target, not a fabricated string.
"""
import asyncio
import re
from typing import Optional, Tuple

from app.core.config import settings

WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS-SSN",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle-DB", 2049: "NFS",
    3000: "HTTP-Dev", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9200: "Elasticsearch",
    9300: "Elasticsearch-Transport", 11211: "Memcached", 27017: "MongoDB",
    6380: "Redis-Alt",
}


def guess_service(port: int) -> str:
    return WELL_KNOWN_PORTS.get(port, "Unknown")


async def grab_banner(ip: str, port: int) -> Optional[str]:
    """Best-effort banner grab. Returns None if nothing was received."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=1.0)
    except Exception:
        return None

    banner = b""
    try:
        # Most services that "talk first" (SSH, FTP, SMTP, POP3, IMAP) will
        # send a banner within a second of connecting.
        try:
            banner = await asyncio.wait_for(
                reader.read(settings.BANNER_READ_BYTES), timeout=settings.BANNER_READ_TIMEOUT
            )
        except asyncio.TimeoutError:
            banner = b""

        # Silent protocols (many HTTP servers) need a nudge.
        if not banner:
            try:
                writer.write(b"\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(
                    reader.read(settings.BANNER_READ_BYTES), timeout=settings.BANNER_READ_TIMEOUT
                )
            except Exception:
                banner = b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if not banner:
        return None
    try:
        return banner.decode("utf-8", errors="replace").strip()[:500]
    except Exception:
        return None


# Ordered (most specific first). Patterns are anchored to protocol greetings
# so a banner that merely *mentions* a word (e.g. an HTTP page containing
# "ssh") is not mislabeled.
_BANNER_RULES = [
    (re.compile(r"^SSH-\d", re.I), "SSH"),
    (re.compile(r"^HTTP/\d", re.I), "HTTP"),
    (re.compile(r"^220[ -].*\b(e?smtp|postfix|exim|sendmail)\b", re.I | re.S), "SMTP"),
    (re.compile(r"^220[ -].*\bftp", re.I | re.S), "FTP"),
    (re.compile(r"^\+OK\b", re.I), "POP3"),
    (re.compile(r"^\* OK\b", re.I), "IMAP"),
    (re.compile(r"mysql|mariadb", re.I), "MySQL"),
    (re.compile(r"^-(NOAUTH|DENIED)\b|^\+PONG|redis_version", re.I), "Redis"),
]


def refine_service_from_banner(port: int, banner: Optional[str]) -> str:
    """Use banner text to sharpen the port-based guess when we have real
    evidence for it. Falls back to the port-based guess otherwise."""
    guess = guess_service(port)
    if not banner:
        return guess

    text = banner.lstrip()
    for pattern, name in _BANNER_RULES:
        if pattern.search(text):
            return name
    # Redis answers the newline nudge with "-ERR ..." only on its usual ports.
    if port in (6379, 6380) and text.startswith("-ERR"):
        return "Redis"
    return guess


_VERSION_RULES = [
    ("SSH", re.compile(r"^SSH-\d\.\d+-([A-Za-z][\w.-]*?)[_ -]?(\d[\w.]*)?(?:\s|$)")),
    ("FTP", re.compile(r"\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server)\b[ /]*v?(\d[\w.]*)?", re.I)),
    ("SMTP", re.compile(r"\b(Postfix|Exim|Sendmail)\b[ /]*(\d[\w.]*)?", re.I)),
    ("Redis", re.compile(r"()redis_version:(\S+)", re.I)),
]


def extract_version(service: str, banner: Optional[str]) -> Optional[str]:
    """Best-effort 'Product 1.2.3' string taken verbatim from banner text.
    Returns None when the banner doesn't state a product/version - it never guesses."""
    if not banner:
        return None
    text = banner.lstrip()
    if service == "MySQL":
        # MariaDB prefixes its real version with a "5.5.5-" replication-compat marker.
        text = re.sub(r"5\.5\.5-(?=\d+\.\d+\.\d+)", "", text)
        m = re.search(r"(\d+\.\d+\.\d+)[\w.+~-]*", text)
        if m:
            product = "MariaDB" if re.search(r"mariadb", text, re.I) else "MySQL"
            return f"{product} {m.group(1)}"
        return None
    for name, pattern in _VERSION_RULES:
        if name != service:
            continue
        m = pattern.search(text)
        if not m:
            return None
        product = (m.group(1) or "").strip("-_ ")
        version = (m.group(2) or "").strip()
        label = f"{product} {version}".strip() if product else f"Redis {version}".strip()
        return label or None
    return None
