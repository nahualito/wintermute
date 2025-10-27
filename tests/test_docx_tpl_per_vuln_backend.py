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

import os
from pathlib import Path
from typing import Any

import pytest
from docx import Document as _Doc

from wintermute.backends.docx_reports import DocxTplPerVulnBackend
from wintermute.findings import ReproductionStep, Risk, Vulnerability
from wintermute.reports import ReportSpec

# Skip if any of the docx libs are missing (keeps CI green without these deps)
docxtpl = pytest.importorskip("docxtpl")
docx = pytest.importorskip("docx")
docxcompose = pytest.importorskip("docxcompose")


def _make_template(path: Path, text: str) -> None:
    """
    Create a minimal .docx file at `path` with `text` content.
    docxtpl renders from any valid .docx that contains its Jinja placeholders.
    """
    d = _Doc()
    d.add_paragraph(text)
    d.save(str(path))


def test_docxtpl_per_vuln_backend_renders_and_saves(tmp_path: Any) -> None:
    # Prepare templates directory and files
    tdir = Path(tmp_path) / "templates"
    tdir.mkdir(parents=True, exist_ok=True)

    # Main template: placeholders for title/author/created_at/summary
    main_t = tdir / "report_main.docx"
    _make_template(
        main_t, "{{ title }} | {{ author }} | {{ created_at }}\n{{ summary }}"
    )

    # Per-vuln template: placeholders for vuln fields and a manual page-break marker
    vuln_t = tdir / "report_vuln.docx"
    _make_template(
        vuln_t,
        "### {{ title }} ({{ context_path }})\n"
        "{{ description }}\n"
        "{% if risk %}Severity: {{ risk.severity }}{% endif %}\n"
        "{% if reproduction_steps %}{% for rs in reproduction_steps %}- {{ rs.title }}{% endfor %}{% endif %}\n",
    )

    b = DocxTplPerVulnBackend(
        template_dir=str(tdir),
        main_template="report_main.docx",
        vuln_template="report_vuln.docx",
    )

    spec = ReportSpec(title="Tpl Test", author="Unit")
    b.begin(spec)
    b.add_summary("Hello world.")
    b.add_vulnerability(
        Vulnerability(
            title="S3 public",
            description="Bucket allows public read",
            risk=Risk(likelihood="High", impact="Medium", severity="High"),
            reproduction_steps=[
                ReproductionStep(title="List", tool="aws", action="s3 ls")
            ],
            verified=True,
        ),
        context_path="CloudAccount[name=aws-prod].vulnerabilities[0]",
    )
    b.add_vulnerability(
        Vulnerability(title="Legacy TLS", description="TLS 1.0 enabled")
    )

    # finalize() should return non-trivial bytes of a .docx
    blob = b.finalize()
    assert isinstance(blob, (bytes, bytearray))
    assert len(blob) > 600  # zipped docx files will be >= ~600 bytes even when tiny

    # save() should write to disk
    out_path = Path(tmp_path) / "out.docx"
    b.begin(spec)  # fresh document
    b.add_summary("Again.")
    b.save(str(out_path))
    assert os.path.exists(out_path) and os.path.getsize(out_path) > 600
