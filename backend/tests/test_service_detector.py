import pytest

from app.scanner.service_detector import refine_service_from_banner as refine


@pytest.mark.parametrize("port,banner,expected", [
    (22, "SSH-2.0-OpenSSH_9.6", "SSH"),
    (2222, "SSH-2.0-dropbear", "SSH"),
    (21, "220 (vsFTPd 3.0.5) FTP ready", "FTP"),
    (25, "220 mail.example.com ESMTP Postfix", "SMTP"),
    (8080, "HTTP/1.1 400 Bad Request", "HTTP"),
    (110, "+OK Dovecot ready.", "POP3"),
    (143, "* OK IMAP4rev1 ready", "IMAP"),
    (6379, "-ERR unknown command ''", "Redis"),
    (3306, "5.7.42-MariaDB", "MySQL"),
])
def test_banner_identification(port, banner, expected):
    assert refine(port, banner) == expected


def test_word_in_body_does_not_mislabel():
    # An HTTP-ish page that merely mentions ssh/ftp must not become SSH/FTP.
    assert refine(9999, "<html>Enable ssh and ftp in settings</html>") == "Unknown"


def test_no_banner_falls_back_to_port_guess():
    assert refine(443, None) == "HTTPS"
