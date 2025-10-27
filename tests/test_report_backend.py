# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use, line-too-long
#
# MIT License
#
# Copyright (c) 2024,2025 Enrique Alfonso Sanchez Montellano (nahualito)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import pytest

from wintermute.basemodels import CloudAccount, Peripheral
from wintermute.findings import ReproductionStep, Risk, Vulnerability
from wintermute.reports import (
    RenderedReport,
    Report,
    ReportBackend,
    ReportSpec,
    collect_vulnerabilities,
)

# -------------------------
# Fake backend (typed)
# -------------------------


@dataclass
class _FakeBackend(ReportBackend):
    began: bool = False
    finalized: bool = False
    saved_path: Optional[str] = None
    summary_text: Optional[str] = None
    vulns: List[Tuple[Vulnerability, Optional[str]]] = field(default_factory=list)

    def begin(self, spec: ReportSpec) -> None:
        self.began = True

    def add_summary(self, text: str) -> None:
        self.summary_text = text

    def add_vulnerability(
        self, vuln: Vulnerability, *, context_path: Optional[str] = None
    ) -> None:
        self.vulns.append((vuln, context_path))

    def finalize(self) -> bytes:
        self.finalized = True
        # Return bytes encoding (#vulns, summary present flag)
        n = len(self.vulns)
        s = "1" if self.summary_text else "0"
        return f"FAKE:{n}:{s}".encode("utf-8")

    def save(self, path: str) -> None:
        self.saved_path = path


# -------------------------
# Small helper model for traversal sanity
# -------------------------


@dataclass
class _Operation:
    name: str
    accounts: List[CloudAccount]
    peripherals: List[Peripheral]
    misc: Dict[str, Any]


# -------------------------
# Facade & collector tests
# -------------------------


def test_report_register_render_save_and_counts(tmp_path: Any) -> None:
    backend = _FakeBackend()
    Report.register_backend("fake", backend, make_default=True)

    acct = CloudAccount(
        name="aws-prod",
        vulnerabilities=[
            Vulnerability(
                title="Public S3",
                description="Bucket allows public read",
                risk=Risk(likelihood="High", impact="Medium", severity="High"),
                reproduction_steps=[ReproductionStep(title="List objects", tool="aws")],
                verified=True,
            )
        ],
    )
    periph = Peripheral(
        name="UART0",
        pType="UART",
        vulnerabilities=[
            Vulnerability(
                title="No console auth", description="UART console lacks auth"
            )
        ],
    )
    extra: Dict[str, Any] = {
        "service": {
            "vulnerabilities": [{"title": "Old TLS", "description": "TLS 1.0 enabled"}]
        }
    }

    spec = ReportSpec(
        title="Q4 Security Assessment", author="Unit", summary="Posture improving."
    )
    rendered: RenderedReport = Report.render(
        spec, [acct, periph, extra], include_summary=True
    )
    out = rendered.bytes_.decode("utf-8")
    assert out == "FAKE:3:1"  # 3 vulns, summary present

    out_path = tmp_path / "out.fake"
    Report.save(spec, [acct, periph], str(out_path), include_summary=False)
    assert backend.saved_path == str(out_path)


def test_collect_vulnerabilities_on_operation_root_and_contexts() -> None:
    acct = CloudAccount(
        name="aws-dev",
        vulnerabilities=[
            Vulnerability(title="IAM wildcard", description="* in policy")
        ],
    )
    periph = Peripheral(
        name="DBG",
        pType="UART",
        vulnerabilities=[
            Vulnerability(title="Debug pins exposed", description="JTAG open")
        ],
    )
    op = _Operation(
        name="Engagement",
        accounts=[acct],
        peripherals=[periph],
        misc={
            "legacy": {
                "vulnerabilities": [{"title": "Old OpenSSH", "description": "7.4p1"}]
            }
        },
    )

    items: List[Tuple[Vulnerability, str]] = list(collect_vulnerabilities([op]))
    titles = {v.title for v, _ in items}
    assert {"IAM wildcard", "Debug pins exposed", "Old OpenSSH"} <= titles

    ctxs = [ctx for _, ctx in items]
    # Root context should mention Operation name
    assert any("Operation[name=Engagement]" in s for s in ctxs)
    # CloudAccount/Peripheral name contexts
    assert any(".accounts[0].vulnerabilities[0]" in s for s in ctxs)
    assert any(".peripherals[0].vulnerabilities[0]" in s for s in ctxs)


def test_collect_vulnerabilities_does_not_coerce_basemodel_class_metadata() -> None:
    """
    Regression test for the earlier crash where collector descended into BaseModel
    class dicts (JSON_ADAPTERS/PARSERS) and tried to Vulnerability.from_dict them.
    Passing a CloudAccount ensures BaseModel is in play; no exception should occur.
    """
    acct = CloudAccount(name="empty")
    # Should simply yield nothing and not crash
    items = list(collect_vulnerabilities([acct]))
    assert items == []


def test_render_without_backend_raises_runtimeerror(monkeypatch: Any) -> None:
    # Temporarily clear the default backend
    # Note: This reaches into the class attributes intentionally for the test.
    from wintermute import reports as _r

    orig = _r.Report._backend
    _r.Report._backend = None
    try:
        with pytest.raises(RuntimeError):
            Report.render(ReportSpec(title="x"), [], include_summary=False)
    finally:
        _r.Report._backend = orig
