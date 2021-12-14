import random
import string

import log4j_scanner


def test_obfuscate_string():
    test = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
    result = log4j_scanner.obfuscate_string(test)
    assert "[CHAR]" not in result, "Not all replaced"
    for char in test:
        assert char in result, f"Character {char} not in {result}"


def test_create_payload():
    target_domain = "hard.to.imagine.com"
    callback_domain = "example.com"
    payload = log4j_scanner.create_payload(callback_domain, "dns", "asdf", target_domain, True)

    assert target_domain in payload, f"Target domain not in payload: {payload}"

    payload = log4j_scanner.create_payload(callback_domain, "dns", "asdf", target_domain, False)
    assert target_domain not in payload, f"Target domain is in payload: {payload}"
