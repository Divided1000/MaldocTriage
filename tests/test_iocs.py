from maldoc_triage import iocs


def test_extract_url():
    out = iocs.extract_all(b"go to http://evil.test/a?b=1 now")
    assert "http://evil.test/a?b=1" in out["urls"]


def test_extract_ipv4():
    out = iocs.extract_all(b"c2 at 203.0.113.45 online")
    assert "203.0.113.45" in out["ipv4"]


def test_extract_domain():
    out = iocs.extract_all(b"contact bad-domain.example for info")
    assert "bad-domain.example" in out.get("domains", [])


def test_filename_tld_is_not_a_domain():
    out = iocs.extract_all(b"loaded kernel32.dll and setup.exe")
    assert "kernel32.dll" not in out.get("domains", [])
    assert "setup.exe" not in out.get("domains", [])


def test_utf16_url_extraction():
    data = "http://wide.example/x".encode("utf-16-le")
    out = iocs.extract_all(data)
    assert any("wide.example" in u for u in out.get("urls", []))
