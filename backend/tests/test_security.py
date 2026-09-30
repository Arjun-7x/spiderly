import pytest
from app.core.security import ValidationError, parse_port_spec, validate_scan_mode, validate_target


def test_valid_ipv4():
    assert validate_target("192.168.1.10") == "192.168.1.10"


def test_valid_hostname():
    assert validate_target("scanme.example.com") == "scanme.example.com"


def test_rejects_shell_metacharacters():
    with pytest.raises(ValidationError):
        validate_target("127.0.0.1; rm -rf /")


def test_rejects_empty_target():
    with pytest.raises(ValidationError):
        validate_target("")


def test_parse_single_port():
    assert parse_port_spec("22") == [22]


def test_parse_range():
    assert parse_port_spec("20-23") == [20, 21, 22, 23]


def test_parse_mixed():
    assert parse_port_spec("22,80,1000-1002") == [22, 80, 1000, 1001, 1002]


def test_rejects_invalid_port():
    with pytest.raises(ValidationError):
        parse_port_spec("70000")


def test_rejects_huge_range():
    with pytest.raises(ValidationError):
        parse_port_spec("1-65535")


def test_rejects_shell_injection_in_ports():
    with pytest.raises(ValidationError):
        parse_port_spec("22; cat /etc/passwd")


def test_scan_mode_validation():
    assert validate_scan_mode("quick") == "quick"
    with pytest.raises(ValidationError):
        validate_scan_mode("delete_everything")


@pytest.mark.parametrize("spec", ["80-", "-", "1-2-3", "abc", "80,,-", "22;ls", "0", "99999", "-5"])
def test_malformed_port_specs_raise_validation_error(spec):
    with pytest.raises(ValidationError):
        parse_port_spec(spec)


def test_target_is_stripped_before_validation():
    assert validate_target("  10.0.0.5 ") == "10.0.0.5"


# ---- target policy ----
import ipaddress

from app.core.config import settings
from app.core.security import check_target_policy


@pytest.mark.parametrize("addr", ["169.254.169.254", "0.0.0.0", "224.0.0.1", "fe80::1", "::ffff:169.254.169.254"])
def test_policy_always_blocks_dangerous_ranges(addr):
    with pytest.raises(ValidationError):
        check_target_policy(addr)


def test_policy_allows_loopback_by_default():
    check_target_policy("127.0.0.1")


def test_policy_can_block_private(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", False)
    for addr in ("127.0.0.1", "10.1.2.3", "192.168.0.9"):
        with pytest.raises(ValidationError):
            check_target_policy(addr)
    check_target_policy("93.184.216.34")


def test_policy_allowlist(monkeypatch):
    monkeypatch.setattr(settings, "ALLOWED_TARGET_NETWORKS", [ipaddress.ip_network("10.0.0.0/24")])
    check_target_policy("10.0.0.7")
    with pytest.raises(ValidationError):
        check_target_policy("10.0.1.7")
