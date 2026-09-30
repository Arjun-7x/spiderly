"""Keep secrets out of logs.

WebSocket and report links can't send headers, so the API key travels as
?api_key=... Uvicorn logs the full request path, which would put the key in
every log aggregator (Render, Docker, ...). This filter redacts it.
"""
import logging
import re

_KEY_RE = re.compile(r"(api_key=)[^&\s\"']+", re.I)


def redact(text: str) -> str:
    return _KEY_RE.sub(r"\1[REDACTED]", text)


class RedactApiKeyFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
        elif isinstance(record.args, dict):
            record.args = {k: redact(v) if isinstance(v, str) else v for k, v in record.args.items()}
        return True


def install() -> None:
    for name in ("uvicorn.access", "uvicorn.error", "uvicorn", "spiderly", ""):
        logging.getLogger(name).addFilter(RedactApiKeyFilter())
