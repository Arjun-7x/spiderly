"""
SPIDERLY - Safe HTTP metadata collection.

For ports that look like they're speaking HTTP(S), SPIDERLY performs a
single GET request and records passive metadata only: status code,
Server header, page title, content type, redirect target, and whether
TLS was used. No crawling, no form submission, no destructive requests,
no automated exploitation.
"""
import re
from dataclasses import dataclass
from typing import Optional

import httpx

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

HTTP_LIKE_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000}


@dataclass
class HttpInfo:
    status_code: Optional[int]
    server_header: Optional[str]
    title: Optional[str]
    content_type: Optional[str]
    tls: bool
    redirect_location: Optional[str]


def looks_like_http(port: int) -> bool:
    return port in HTTP_LIKE_PORTS


async def fetch_metadata(ip: str, port: int) -> Optional[HttpInfo]:
    schemes = ["https", "http"] if port in (443, 8443) else ["http", "https"]
    async with httpx.AsyncClient(verify=False, timeout=3.0, follow_redirects=False) as client:
        for scheme in schemes:
            url = f"{scheme}://{ip}:{port}/"
            try:
                resp = await client.get(url)
            except Exception:
                continue

            title = None
            content_type = resp.headers.get("content-type", "")
            if "text/html" in content_type.lower():
                match = TITLE_RE.search(resp.text or "")
                if match:
                    title = re.sub(r"\s+", " ", match.group(1)).strip()[:200]

            return HttpInfo(
                status_code=resp.status_code,
                server_header=resp.headers.get("server"),
                title=title,
                content_type=content_type or None,
                tls=(scheme == "https"),
                redirect_location=resp.headers.get("location"),
            )
    return None
