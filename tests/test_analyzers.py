from maldoc_triage.engine import scan_bytes

import samples


def _ids(report):
    return {f.id for f in report.findings}


# -- OOXML -----------------------------------------------------------------

def test_ooxml_benign_is_low_risk():
    r = scan_bytes(samples.ooxml_benign())
    assert r.file_type == "ooxml"
    assert r.risk in ("clean", "low")
    assert "ooxml.vba_macro" not in _ids(r)


def test_ooxml_macro_detected():
    r = scan_bytes(samples.ooxml_macro())
    ids = _ids(r)
    assert "ooxml.vba_macro" in ids
    assert "ooxml.vba_autoexec" in ids
    assert r.risk in ("high", "critical")


def test_ooxml_template_injection_detected():
    r = scan_bytes(samples.ooxml_template_injection())
    ids = _ids(r)
    assert "ooxml.template_injection" in ids
    assert r.risk == "critical"
    # The remote template URL should be captured as an IOC.
    assert any("evil.example.com" in u for u in r.iocs.get("urls", []))


def test_ooxml_dde_detected():
    r = scan_bytes(samples.ooxml_dde())
    assert "ooxml.dde" in _ids(r)


# -- OLE -------------------------------------------------------------------

def test_ole_benign():
    r = scan_bytes(samples.ole_benign())
    assert r.file_type == "ole"
    assert "ole.vba_macro" not in _ids(r)


def test_ole_macro_detected():
    r = scan_bytes(samples.ole_macro())
    ids = _ids(r)
    assert "ole.vba_macro" in ids
    assert "ole.vba_autoexec" in ids
    assert "ole.suspicious_api" in ids
    assert r.risk in ("high", "critical")


# -- PDF -------------------------------------------------------------------

def test_pdf_benign():
    r = scan_bytes(samples.pdf_benign())
    assert r.file_type == "pdf"
    assert "pdf.javascript" not in _ids(r)
    assert r.risk in ("clean", "low")


def test_pdf_malicious_detected():
    r = scan_bytes(samples.pdf_malicious())
    ids = _ids(r)
    assert "pdf.javascript" in ids
    assert "pdf.openaction" in ids
    assert "pdf.launch" in ids
    assert r.risk == "critical"


def test_pdf_obfuscation_detected():
    r = scan_bytes(samples.pdf_obfuscated_js())
    ids = _ids(r)
    assert "pdf.name_obfuscation" in ids
    assert "pdf.javascript" in ids


# -- RTF -------------------------------------------------------------------

def test_rtf_benign():
    r = scan_bytes(samples.rtf_benign())
    assert r.file_type == "rtf"
    assert "rtf.embedded_object" not in _ids(r)


def test_rtf_malicious_detected():
    r = scan_bytes(samples.rtf_malicious())
    ids = _ids(r)
    assert "rtf.embedded_object" in ids
    assert "rtf.objupdate" in ids
    assert "rtf.equation_editor" in ids
    assert r.risk in ("high", "critical")
    assert any("malware.example.com" in u for u in r.iocs.get("urls", []))


# -- generic ---------------------------------------------------------------

def test_unknown_type_still_sweeps_iocs():
    r = scan_bytes(b"plain text with http://x.example/path inside")
    assert r.file_type == "unknown"
    assert "core.unsupported_type" in _ids(r)
    assert any("x.example" in u for u in r.iocs.get("urls", []))


def test_sha256_is_computed():
    r = scan_bytes(b"abc")
    # sha256("abc")
    assert r.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
