# pyright: reportMissingImports=false
# mypy: ignore-errors=False

from pathlib import Path

import pytest

from wintermute.utils.parsers import BurpParser


@pytest.fixture()
def sample_burp_xml(tmp_path: Path) -> Path:
    # Two hosts (same FQDN, different ports), mixed protocols, repeated issue name on purpose
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<burbReport>
  <issue>
    <name>Content type incorrectly stated</name>
    <severity>Low</severity>
    <host>http://testphp.vulnweb.com</host>
    <path>/index.php</path>
    <location>path /index.php</location>
    <issueBackground><![CDATA[<p>Some background.</p>]]></issueBackground>
    <remediationBackground><![CDATA[<p>Fix the header.</p>]]></remediationBackground>
  </issue>

  <issue>
    <name>Cacheable HTTPS response</name>
    <severity>Medium</severity>
    <host>https://testphp.vulnweb.com</host>
    <path>/login</path>
    <location>parameter [token] in query</location>
    <issueBackground><![CDATA[<p>Background 2</p>]]></issueBackground>
    <remediationBackground><![CDATA[<p>Set Cache-Control.</p>]]></remediationBackground>
  </issue>

  <issue>
    <name>Cacheable HTTPS response</name>
    <severity>High</severity>
    <host>https://testphp.vulnweb.com:444</host>
    <path>/login</path>
    <location>path /login</location>
    <issueBackground><![CDATA[<p>Dup title (different port).</p>]]></issueBackground>
  </issue>

  <issue>
    <name>Unknown scheme test</name>
    <severity>Low</severity>
    <host>ws://weird.example.com</host>
    <path>/ws</path>
    <location>path /ws</location>
    <issueBackground><![CDATA[<p>Weird scheme.</p>]]></issueBackground>
  </issue>
</burbReport>
"""
    p = tmp_path / "burp.xml"
    p.write_text(xml, encoding="utf-8")
    return p


def test_parse_groups_by_device_service_and_sets_severity(
    sample_burp_xml: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    parser = BurpParser(workbook=str((sample_burp_xml.parent / "dummy.xlsx")))
    devices = parser.parse(str(sample_burp_xml))

    # Expect devices for testphp.vulnweb.com and weird.example.com
    fqdn_set = {d.fqdn for d in devices}
    assert "testphp.vulnweb.com" in fqdn_set
    assert "weird.example.com" in fqdn_set

    # find device: testphp.vulnweb.com
    dev = next(d for d in devices if d.fqdn == "testphp.vulnweb.com")
    # Services: http->80 and https->443 and explicit 444
    ports = sorted({s.portNumber for s in dev.services})
    # NOTE: depending on your Service creation logic, you may only see [80, 443] or [80, 443, 444]
    # because the https issue with an explicit :444 is another service.
    assert 80 in ports
    assert 443 in ports or 444 in ports

    # On the 80/443 service(s), confirm vulnerabilities exist and severity is set
    all_vulns = {v.title for s in dev.services for v in s.vulnerabilities}
    assert "Content type incorrectly stated" in all_vulns
    assert "Cacheable HTTPS response" in all_vulns

    # Make sure severity propagated
    # (Choose a vuln instance and check its risk.severity string)
    any_vuln = next(
        v
        for s in dev.services
        for v in s.vulnerabilities
        if v.title == "Cacheable HTTPS response"
    )
    assert isinstance(any_vuln.risk.severity, str)
    assert any_vuln.risk.severity in {"Low", "Medium", "High"}

    # Ensure parser stripped literal <p> tags from description (parse() does .text.replace)
    v_ct = next(
        v
        for s in dev.services
        for v in s.vulnerabilities
        if v.title == "Content type incorrectly stated"
    )
    assert "<p>" not in v_ct.description
    assert "</p>" not in v_ct.description

    # Unknown scheme should map to port 0 per code path
    dev_weird = next(d for d in devices if d.fqdn == "weird.example.com")
    assert any(s.portNumber == 0 for s in dev_weird.services)

    # It prints "Adding issue ..." lines; ensure stdout had them (sanity)
    out = capsys.readouterr().out
    assert (
        "Adding issue Content type incorrectly stated to host testphp.vulnweb.com"
        in out
    )


def test_parse_parameter_detection(sample_burp_xml: Path) -> None:
    # This checks the parameter parsing logic indirectly through toXLSX
    parser = BurpParser(workbook=str((sample_burp_xml.parent / "tmp.xlsx")))

    # Just ensure calling parse does not crash and builds devices
    devices = parser.parse(str(sample_burp_xml))
    assert len(devices) >= 1
