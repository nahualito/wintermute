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

import json
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, cast

from docx import Document as _DocxDocumentFactory
from docxcompose.composer import Composer  # type: ignore[import-untyped]

# Runtime imports (untyped libs)
from docxtpl import DocxTemplate  # type: ignore[import-untyped]

from ..core import TestCase, TestCaseRun
from ..findings import Vulnerability
from ..reports import ReportBackend, ReportSpec, ReportType

# --- Type alias for python-docx Document ---
if TYPE_CHECKING:
    from docx.document import Document as DocxDocument  # precise type for mypy
else:
    DocxDocument = Any  # at runtime we don't care; library is untyped

import logging

log = logging.getLogger(__name__)

__category__ = "Reporting"
__description__ = "Automated DOCX report generation using Wintermute templates."


def _vuln_to_context(v: Vulnerability, context_path: Optional[str]) -> Dict[str, Any]:
    """
    Convert a Vulnerability to a JSON-safe dict for docxtpl rendering.
    Ensures mypy gets Dict[str, Any] (json.loads(...) returns Any).
    """
    d = v.to_dict()
    d["context_path"] = context_path or ""
    safe: Dict[str, Any] = cast(Dict[str, Any], json.loads(json.dumps(d)))
    return safe


def _run_to_context(
    run: TestCaseRun, test_case: Optional[TestCase], context_path: Optional[str]
) -> Dict[str, Any]:
    """Merge execution data with test case definitions for the template."""
    # Start with the execution data (status, started_at, etc.)
    ctx = run.to_dict()

    # Inject static Test Case data if available
    if test_case:
        ctx["test_case"] = {
            "name": test_case.name,
            "description": test_case.description,
            "execution_mode": test_case.execution_mode.name,
            "steps": [
                step.to_dict() for step in test_case.steps
            ],  # Includes tool and action
        }
    else:
        ctx["test_case"] = {
            "name": "Unknown",
            "description": "No definition found",
            "steps": [],
        }

    ctx["context_path"] = context_path or ""
    return cast(Dict[str, Any], json.loads(json.dumps(ctx)))


@dataclass
class DocxTplPerVulnBackend(ReportBackend):
    """
    Render a main template and append a per-vulnerability template for each vuln.
    Uses docxtpl + docxcompose.

    Example:
        >>> from wintermute.reports import Report, ReportSpec
        >>> from wintermute.backends.docx_reports import DocxTplPerVulnBackend
        >>> from wintermute.basemodels import CloudAccount, Peripheral
        >>> from wintermute.findings import Vulnerability, ReproductionStep, Risk
        >>> Report.register_backend(
        ...     "word_tpl_per_vuln",
        ...     DocxTplPerVulnBackend(
        ...         template_dir="templates",
        ...         main_template="report_main.docx",
        ...         vuln_template="report_vuln.docx",
        ...     ),
        ...     make_default=True,
        ... )
        >>> acct = CloudAccount(
        >>>     name="aws-prod",
        ...     vulnerabilities=[
        ...         Vulnerability(
        ...             title="S3 bucket public",
        ...             description="Bucket allows public read",
        ...             risk=Risk(likelihood="High", impact="Medium", severity="High"),
        ...             reproduction_steps=[
        ...                 ReproductionStep(title="List objects", tool="aws", action="s3 ls", arguments=["s3://bucket"])
        ...             ],
        ...             verified=True,
        ...         )
        ...     ],
        ... )
        >>> periph = Peripheral(
        ...     name="UART0",
        ...     pType="UART",
        ...     vulnerabilities=[
        ...         Vulnerability(
        ...             title="No console auth",
        ...             description="UART console lacks auth",
        ...             cvss=6,
        ...             verified=False,
        ...         )
        ...     ],
        ... )
        >>> spec = ReportSpec(
        ...     title="Security Assessment – Q4",
        ...     author="Enrique",
        ...     summary="Overall posture is improving. Top issues: public S3 access, UART console auth.",
        ... )
        >>> Report.save(spec, [acct, periph], "out.docx")

    Attributes:
        template_dir: Directory containing the docx templates.
        main_template: Filename of the main report template.
        vuln_template: Filename of the per-vulnerability template.
    """

    template_dir: str
    main_template: str = "report_main.docx"
    vuln_template: str = "report_vuln.docx"
    test_run_template: str = "report_test_run.docx"

    _spec: Optional[ReportSpec] = None
    _summary: str = ""
    _vuln_contexts: List[Dict[str, Any]] = None  # type: ignore[assignment]
    _run_contexts: List[Dict[str, Any]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._vuln_contexts is None:
            self._vuln_contexts = []
        if self._run_contexts is None:
            self._run_contexts = []

    def begin(self, spec: ReportSpec) -> None:
        self._spec = spec
        self._summary = spec.summary or ""
        self._vuln_contexts = []
        self._run_contexts = []

    def add_summary(self, text: str) -> None:
        self._summary = text

    def add_test_run(
        self,
        run: TestCaseRun,
        test_case: Optional[TestCase] = None,
        *,
        context_path: Optional[str] = None,
    ) -> None:
        # Helper to convert TestCaseRun to dict for docxtpl
        d = run.to_dict()
        d["context_path"] = context_path or ""
        safe = _run_to_context(run, test_case, context_path)
        self._run_contexts.append(safe)

    def add_vulnerability(
        self, vuln: Vulnerability, *, context_path: Optional[str] = None
    ) -> None:
        self._vuln_contexts.append(_vuln_to_context(vuln, context_path))

    # --- internal rendering helpers ---

    def _render_main(self) -> DocxDocument:
        assert self._spec is not None
        tdir = Path(self.template_dir)
        tpl = DocxTemplate(str(tdir / self.main_template))
        context: Dict[str, Any] = {
            "title": self._spec.title,
            "author": self._spec.author or "",
            "created_at": self._spec.created_at.strftime("%B %d, %Y"),
            "summary": self._summary,
            "options": self._spec.options,
        }
        tpl.render(context)
        log.debug("Rendered main template with context: %s", context)
        # Save to memory and re-open as python-docx Document for composition
        bio = BytesIO()
        tpl.save(bio)
        bio.seek(0)
        doc: DocxDocument = _DocxDocumentFactory(bio)
        log.info("Main report document rendered successfully.")
        return doc

    def _render_content_docs(self) -> List[DocxDocument]:
        tdir = Path(self.template_dir)
        results: List[DocxDocument] = []

        # Render whichever list has content based on the spec type
        if self._spec and self._spec.report_type == ReportType.VULNERABILITY:
            for ctx in self._vuln_contexts:
                results.append(
                    self._render_single_template(tdir / self.vuln_template, ctx)
                )

        elif self._spec and self._spec.report_type == ReportType.TEST_PLAN:
            for ctx in self._run_contexts:
                results.append(
                    self._render_single_template(tdir / self.test_run_template, ctx)
                )

        return results

    def _render_single_template(
        self, tpl_path: Path, context: Dict[str, Any]
    ) -> DocxDocument:
        tpl = DocxTemplate(str(tpl_path))
        tpl.render(context)
        bio = BytesIO()
        tpl.save(bio)
        bio.seek(0)
        return _DocxDocumentFactory(bio)

    def _compose(self) -> DocxDocument:
        base = self._render_main()
        comp = Composer(base)
        header_text = None

        assert self._spec is not None

        if self._spec.report_type == ReportType.TEST_PLAN and self._run_contexts:
            header_text = "Test Case Executions"
        elif self._vuln_contexts:
            header_text = "Vulnerabilities"

        if header_text:
            comp.doc.add_page_break()
            comp.doc.add_heading(header_text, level=2)

        for d in self._render_content_docs():
            comp.append(d)
        log.info("Composed final document with all content.")
        return base

    # --- public API ---

    def finalize(self) -> bytes:
        doc = self._compose()  # DocxDocument (non-Optional)
        out = BytesIO()
        doc.save(out)
        log.info("Finalized report document in memory.")
        return out.getvalue()

    def save(self, path: str) -> None:
        doc = self._compose()  # DocxDocument (non-Optional)
        doc.save(path)
        log.info(f"Saved report document to {path}")
