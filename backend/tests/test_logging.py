import logging

from app.core.logging_utils import RedactApiKeyFilter, redact


def test_redact_strips_key_but_keeps_rest_of_url():
    assert redact("/api/ws/scans/abc?api_key=SECRET&x=1") == "/api/ws/scans/abc?api_key=[REDACTED]&x=1"
    assert redact("GET /api/reports/abc?api_key=SeCr3t HTTP/1.1") == "GET /api/reports/abc?api_key=[REDACTED] HTTP/1.1"
    assert redact("/api/scans") == "/api/scans"


def test_uvicorn_style_access_record_is_scrubbed():
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0,
                            '%s - "%s %s HTTP/%s" %d', ("1.2.3.4:5", "GET", "/api/reports/x?api_key=TOPSECRET", "1.1", 200), None)
    assert RedactApiKeyFilter().filter(rec)
    assert "TOPSECRET" not in rec.getMessage()
    assert "[REDACTED]" in rec.getMessage()


def test_filter_is_installed_on_uvicorn_loggers():
    import app.main  # noqa: F401
    for name in ("uvicorn.access", "uvicorn.error"):
        assert any(isinstance(f, RedactApiKeyFilter) for f in logging.getLogger(name).filters)
