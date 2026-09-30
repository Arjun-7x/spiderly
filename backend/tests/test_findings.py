from app.scanner.findings import evaluate_open_port, evaluate_http, SEVERITY_MEDIUM, SEVERITY_INFO


def test_open_port_always_produces_info_finding():
    results = evaluate_open_port(8080, "HTTP-Proxy", None)
    assert any(f.severity == SEVERITY_INFO for f in results)


def test_telnet_produces_medium_severity():
    results = evaluate_open_port(23, "Telnet", "Telnet banner")
    severities = [f.severity for f in results]
    assert SEVERITY_MEDIUM in severities


def test_no_high_severity_without_evidence():
    # A generic open port must never be auto-labeled HIGH severity.
    results = evaluate_open_port(9999, "Unknown", None)
    assert all(f.severity != "HIGH" for f in results)


def test_http_without_tls_flagged():
    results = evaluate_http(80, 200, "nginx", tls=False, title="Home")
    assert any("Unencrypted" in f.title for f in results)


def test_https_not_flagged_for_encryption():
    results = evaluate_http(443, 200, None, tls=True, title="Home")
    assert not any("Unencrypted" in f.title for f in results)


def test_specific_rule_replaces_baseline_finding():
    results = evaluate_open_port(23, "Telnet", None)
    titles = [f.title for f in results]
    assert "Telnet service detected" in titles
    assert not any(t.startswith("Open TCP port") for t in titles)


def test_generic_port_gets_exactly_one_baseline_finding():
    results = evaluate_open_port(9999, "Unknown", None)
    assert len(results) == 1 and results[0].severity == SEVERITY_INFO
