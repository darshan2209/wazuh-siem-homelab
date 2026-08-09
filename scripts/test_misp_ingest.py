"""Tests for the MISP ingest validation logic.

The validator is the security-relevant part: MISP attributes are attacker-
influenceable, and these files are parsed by Zeek and Wazuh, so a bad value must
never reach them. Pure functions, no network.

    pip install requests pytest
    pytest test_misp_ingest.py -v
"""

import pytest
import misp_ingest as m


# ---------------------------------------------------------------- ADDR ------

@pytest.mark.parametrize("value", ["8.8.8.8", "1.1.1.1", "9.9.9.9", "45.33.32.156"])
def test_public_ips_valid(value):
    assert m.valid("ADDR", value) is True


@pytest.mark.parametrize("value", [
    "10.0.0.1",        # private, must be rejected: would blocklist your own net
    "192.168.1.1",     # private
    "127.0.0.1",       # loopback
    "0.0.0.0",         # unspecified
    "not-an-ip",
    "8.8.8.8\n1.2.3.4",  # embedded newline would corrupt the list file
    "",
])
def test_bad_ips_rejected(value):
    assert m.valid("ADDR", value) is False


# -------------------------------------------------------------- DOMAIN ------

@pytest.mark.parametrize("value", ["evil.example.com", "a.co", "sub.domain.example.org"])
def test_domains_valid(value):
    assert m.valid("DOMAIN", value) is True


@pytest.mark.parametrize("value", [
    "notadomain",          # no dot
    "has space.com",
    "bad_underscore.com",
    "trailing-.com",
    "a" * 300 + ".com",    # over length
    "evil.com\tinjected",
])
def test_bad_domains_rejected(value):
    assert m.valid("DOMAIN", value) is False


# ------------------------------------------------------------ FILE_HASH -----

@pytest.mark.parametrize("value", [
    "d41d8cd98f00b204e9800998ecf8427e",                                  # md5
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",                          # sha1
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256
])
def test_hashes_valid(value):
    assert m.valid("FILE_HASH", value) is True


@pytest.mark.parametrize("value", ["xyz", "12345", "g" * 32, ""])
def test_bad_hashes_rejected(value):
    assert m.valid("FILE_HASH", value) is False


# ---------------------------------------------------------------- URL -------

@pytest.mark.parametrize("value", ["http://evil.example.com/x", "https://a.example.org/p?q=1"])
def test_urls_valid(value):
    assert m.valid("URL", value) is True


@pytest.mark.parametrize("value", [
    "ftp://evil.com",       # wrong scheme
    "not a url",
    "http://has space.com",
    "javascript:alert(1)",
])
def test_bad_urls_rejected(value):
    assert m.valid("URL", value) is False


# control characters, any kind, are always rejected
@pytest.mark.parametrize("value", ["a\x00b.com", "x\ry.com", "t\tt.com"])
def test_control_characters_rejected(value):
    assert m.valid("DOMAIN", value) is False


# an unknown attribute kind is never valid
def test_unknown_kind_rejected():
    assert m.valid("MUTEX", "anything") is False
