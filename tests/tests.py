import random
import string

from log4j_scanner import scanners, utils


def test_obfuscate_dash():
    test = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    result = "".join(utils.obfuscate_dash(c) for c in test)
    for char in test:
        assert char in result, f"Character {char} not in {result}"
        assert f":-{char}" in result, f"Character {char} not properly obfuscated {result}"


def test_obfuscate_lower():
    test = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    result = "".join(utils.obfuscate_lower(c) for c in test)
    for char in test:
        assert char in result, f"Character {char} not in {result}"
        assert f"${{lower:{char}}}" in result, f"Character {char} not properly obfuscated {result}"


def test_obfuscate_upper():
    test = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    result = "".join(utils.obfuscate_upper(c) for c in test)
    for char in test:
        assert char in result, f"Character {char} not in {result}"
        assert f"${{upper:{char}}}" in result, f"Character {char} not properly obfuscated {result}"


def test_create_payload():
    target_domain = "hard.to.imagine.com"
    callback_domain = "example.com"
    scanner = scanners.BaseScanner([], True, None, False)
    payload = scanner.create_payload(callback_domain, "dns", "asdf", target_domain, True)

    assert target_domain in payload, f"Target domain not in payload: {payload}"

    payload = scanner.create_payload(callback_domain, "dns", "asdf", target_domain, False)
    assert target_domain not in payload, f"Target domain is in payload: {payload}"

    payload = scanner.create_payload(callback_domain, "dns", "asdf", target_domain, False, True)
    assert "127.0.0.1#" in payload, f"Bypass not in payload: {payload}"
