# pyright: reportMissingImports=false
# mypy: ignore-errors=False

from pathlib import Path

import pytest

from wintermute.utils.parsers import BurpParser


@pytest.fixture()
def xml_one_issue(tmp_path: Path) -> Path:
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<burbReport>
  <issue>
    <name>Strict transport security not enforced</name>
    <severity>Low</severity>
    <host>https://example.org</host>
    <path>/</path>
    <location>path /</location>
    <issueBackground><![CDATA[<p>HSTS missing.</p>]]></issueBackground>
    <remediationBackground><![CDATA[<p>Add HSTS.</p>]]></remediationBackground>
  </issue>
</burbReport>"""
    p = tmp_path / "single.xml"
    p.write_text(xml, encoding="utf-8")
    return p


@pytest.mark.skipif(
    __import__("importlib.util").util.find_spec("xlsxwriter") is None,
    reason="xlsxwriter not installed",
)
def test_toXLSX_creates_file(xml_one_issue: Path, tmp_path: Path) -> None:
    out_xlsx = tmp_path / "report.xlsx"
    parser = BurpParser(workbook=str(out_xlsx))
    parser.toXLSX(str(xml_one_issue))

    assert out_xlsx.exists(), "XLSX file should be created"
    assert out_xlsx.stat().st_size > 0, "XLSX file should not be empty"
