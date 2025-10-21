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

from ..findings import Vulnerability
from ..reports import ReportBackend, ReportSpec

# --- Type alias for python-docx Document ---
if TYPE_CHECKING:
    from docx.document import Document as DocxDocument  # precise type for mypy
else:
    DocxDocument = Any  # at runtime we don't care; library is untyped


def _vuln_to_context(v: Vulnerability, context_path: Optional[str]) -> Dict[str, Any]:
    """
    Convert a Vulnerability to a JSON-safe dict for docxtpl rendering.
    Ensures mypy gets Dict[str, Any] (json.loads(...) returns Any).
    """
    d = v.to_dict()
    d["context_path"] = context_path or ""
    safe: Dict[str, Any] = cast(Dict[str, Any], json.loads(json.dumps(d)))
    return safe


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
        ...     DocxTplPerVulnBackend(template_dir="templates", main_template="report_main.docx", vuln_template="report_vuln.docx"),
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
        ...         Vulnerability(title="No console auth", description="UART console lacks auth", cvss=6, verified=False)
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

    _spec: Optional[ReportSpec] = None
    _summary: str = ""
    _vuln_contexts: List[Dict[str, Any]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._vuln_contexts is None:
            self._vuln_contexts = []

    def begin(self, spec: ReportSpec) -> None:
        self._spec = spec
        self._summary = spec.summary or ""
        self._vuln_contexts = []

    def add_summary(self, text: str) -> None:
        self._summary = text

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
            "created_at": self._spec.created_at.isoformat(),
            "summary": self._summary,
        }
        tpl.render(context)
        # Save to memory and re-open as python-docx Document for composition
        bio = BytesIO()
        tpl.save(bio)
        bio.seek(0)
        doc: DocxDocument = _DocxDocumentFactory(bio)
        return doc

    def _render_vuln_docs(self) -> List[DocxDocument]:
        tdir = Path(self.template_dir)
        results: List[DocxDocument] = []
        for ctx in self._vuln_contexts:
            tpl = DocxTemplate(str(tdir / self.vuln_template))
            tpl.render(ctx)
            bio = BytesIO()
            tpl.save(bio)
            bio.seek(0)
            doc: DocxDocument = _DocxDocumentFactory(bio)
            results.append(doc)
        return results

    def _compose(self) -> DocxDocument:
        base = self._render_main()
        comp = Composer(base)
        for d in self._render_vuln_docs():
            comp.append(d)
        # Composer mutates `base`, so returning base is correct.
        return base

    # --- public API ---

    def finalize(self) -> bytes:
        doc = self._compose()  # DocxDocument (non-Optional)
        out = BytesIO()
        doc.save(out)
        return out.getvalue()

    def save(self, path: str) -> None:
        doc = self._compose()  # DocxDocument (non-Optional)
        doc.save(path)
