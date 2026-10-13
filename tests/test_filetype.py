from maldoc_triage import filetype

import samples


def test_detect_ooxml():
    assert filetype.detect(samples.ooxml_benign()) == filetype.OOXML


def test_detect_ole():
    assert filetype.detect(samples.ole_benign()) == filetype.OLE


def test_detect_pdf():
    assert filetype.detect(samples.pdf_benign()) == filetype.PDF


def test_detect_rtf():
    assert filetype.detect(samples.rtf_benign()) == filetype.RTF


def test_detect_unknown():
    assert filetype.detect(b"just some plain text") == filetype.UNKNOWN


def test_detect_empty():
    assert filetype.detect(b"") == filetype.UNKNOWN
