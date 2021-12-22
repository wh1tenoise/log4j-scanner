import random
import string

from log4j_scanner import scanners


def test_obfuscate_string():
    test = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    scanner = scanners.BaseScanner(True, None, False)
    result = scanner._obfuscate_string(test)
    assert "[CHAR]" not in result, "Not all replaced"
    for char in test:
        assert char in result, f"Character {char} not in {result}"


def test_create_payload():
    target_domain = "hard.to.imagine.com"
    callback_domain = "example.com"
    scanner = scanners.BaseScanner(True, None, False)
    payload = scanner.create_payload(callback_domain, "dns", "asdf", target_domain, True)

    assert target_domain in payload, f"Target domain not in payload: {payload}"

    payload = scanner.create_payload(callback_domain, "dns", "asdf", target_domain, False)
    assert target_domain not in payload, f"Target domain is in payload: {payload}"

    payload = scanner.create_payload(callback_domain, "dns", "asdf", target_domain, False, True)
    assert "127.0.0.1#" in payload, f"Bypass not in payload: {payload}"
