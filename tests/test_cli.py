import json
import os

from maldoc_triage import cli

import samples


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_cli_clean_exit_zero(tmp_path, capsys):
    path = _write(tmp_path, "ok.docx", samples.ooxml_benign())
    code = cli.main([path])
    assert code == cli.EXIT_CLEAN


def test_cli_high_exit_two(tmp_path, capsys):
    path = _write(tmp_path, "bad.pdf", samples.pdf_malicious())
    code = cli.main([path])
    assert code == cli.EXIT_HIGH
    out = capsys.readouterr().out
    assert "CRITICAL" in out or "critical" in out


def test_cli_json_output(tmp_path, capsys):
    path = _write(tmp_path, "bad.rtf", samples.rtf_malicious())
    code = cli.main(["--json", path])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["file_type"] == "rtf"
    assert data[0]["risk"] in ("high", "critical")
    assert code == cli.EXIT_HIGH


def test_cli_recursive_directory(tmp_path):
    _write(tmp_path, "a.pdf", samples.pdf_benign())
    _write(tmp_path, "b.pdf", samples.pdf_malicious())
    code = cli.main(["--recursive", str(tmp_path)])
    assert code == cli.EXIT_HIGH


def test_cli_min_severity_filter(tmp_path, capsys):
    clean = _write(tmp_path, "clean.docx", samples.ooxml_benign())
    code = cli.main(["--min-severity", "high", clean])
    # Clean file filtered out, but exit code still reflects it's clean.
    assert code == cli.EXIT_CLEAN


def test_cli_no_args_is_usage_error(capsys):
    code = cli.main([])
    assert code == cli.EXIT_USAGE
