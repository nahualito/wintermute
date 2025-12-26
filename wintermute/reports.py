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
from datetime import datetime, timezone
from enum import Enum, auto
from typing import (
    Any,
    ClassVar,
    Dict,
    Iterable,
    Iterator,
    Optional,
    Protocol,
    Set,
    Tuple,
    cast,
)

from .basemodels import BaseModel
from .core import TestCase, TestCaseRun
from .findings import Vulnerability

# ---------- Backend protocol ----------


class ReportBackend(Protocol):
    def begin(self, spec: "ReportSpec") -> None: ...
    def add_summary(self, text: str) -> None: ...
    def add_vulnerability(
        self, vuln: Vulnerability, *, context_path: Optional[str] = None
    ) -> None: ...
    def add_test_run(
        self,
        run: TestCaseRun,
        test_case: Optional[TestCase] = None,
        *,
        context_path: Optional[str] = None,
    ) -> None: ...
    def finalize(self) -> bytes: ...
    def save(self, path: str) -> None: ...


# ---------- Report data models ----------


class ReportType(Enum):
    VULNERABILITY = auto()
    TEST_PLAN = auto()


@dataclass
class ReportSpec(BaseModel):
    title: str
    report_type: ReportType = ReportType.VULNERABILITY
    author: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    summary: str = ""

    __schema__ = {}
    __enums__ = {}


@dataclass
class RenderedReport(BaseModel):
    """Convenience wrapper for render results."""

    spec: ReportSpec
    bytes_: bytes

    __schema__ = {"spec": ReportSpec}
    __enums__ = {}


# ---------- Metaclass that injects the facade methods ----------


class ReportMeta(type):
    def __new__(mcls, name: str, bases: Tuple[type, ...], ns: Dict[str, Any]) -> type:
        cls = super().__new__(mcls, name, bases, ns)
        c = cast(type["Report"], cls)

        if not hasattr(c, "_backend"):
            c._backend = None
        if not hasattr(c, "_backends"):
            c._backends = {}

        def _require_backend(c_: type["Report"], /) -> ReportBackend:
            b = c_._backend
            if b is None:
                raise RuntimeError(f"No report backend configured for {c_.__name__}")
            return b

        # API we inject (first arg positional-only to appease mypy)
        def set_backend(c_: type["Report"], /, backend: ReportBackend) -> None:
            c_._backend = backend

        def register_backend(
            c_: type["Report"],
            /,
            name: str,
            backend: ReportBackend,
            *,
            make_default: bool = False,
        ) -> None:
            c_._backends[name] = backend
            if make_default or c_._backend is None:
                c_._backend = backend

        def use_backend(c_: type["Report"], /, name: str) -> None:
            c_._backend = c_._backends[name]

        def render(
            c_: type["Report"],
            /,
            spec: ReportSpec,
            objects: Iterable[Any],
            *,
            include_summary: bool = True,
        ) -> RenderedReport:
            backend = _require_backend(c_)
            backend.begin(spec)
            if include_summary and spec.summary:
                backend.add_summary(spec.summary)

            if spec.report_type == ReportType.TEST_PLAN:
                # FIX: Unpack 3 values instead of 2
                for run, tc, ctx in collect_test_runs(objects):
                    backend.add_test_run(run, tc, context_path=ctx)
            else:
                for vuln, ctx in collect_vulnerabilities(objects):
                    backend.add_vulnerability(vuln, context_path=ctx)

            doc = backend.finalize()
            return RenderedReport(spec=spec, bytes_=doc)

        def save(
            c_: type["Report"],
            /,
            spec: ReportSpec,
            objects: Iterable[Any],
            path: str,
            *,
            include_summary: bool = True,
        ) -> None:
            # Render and write atomically via backend.save for efficiency where available
            backend = _require_backend(c_)
            backend.begin(spec)
            if include_summary and spec.summary:
                backend.add_summary(spec.summary)
            for vuln, ctx in collect_vulnerabilities(objects):
                backend.add_vulnerability(vuln, context_path=ctx)
            backend.save(path)

        # Attach as classmethods
        c.set_backend = classmethod(set_backend)  # type: ignore[assignment]
        c.register_backend = classmethod(register_backend)  # type: ignore[assignment]
        c.use_backend = classmethod(use_backend)  # type: ignore[assignment]
        c.render = classmethod(render)  # type: ignore[assignment]
        c.save = classmethod(save)  # type: ignore[assignment]
        return cls


# ---------- Facade class ----------


@dataclass
class Report(BaseModel, metaclass=ReportMeta):
    """Facade class—call Report.render/save regardless of backend.

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
    """

    # You typically won't instantiate Report; the class methods are the API.
    spec: ReportSpec

    _backend: ClassVar[Optional[ReportBackend]] = None
    _backends: ClassVar[Dict[str, ReportBackend]] = {}

    @classmethod
    def set_backend(cls, backend: ReportBackend) -> None:
        raise NotImplementedError

    @classmethod
    def register_backend(
        cls, name: str, backend: ReportBackend, *, make_default: bool = False
    ) -> None:
        raise NotImplementedError

    @classmethod
    def use_backend(cls, name: str) -> None:
        raise NotImplementedError

    @classmethod
    def render(
        cls, spec: ReportSpec, objects: Iterable[Any], *, include_summary: bool = True
    ) -> RenderedReport:
        raise NotImplementedError

    @classmethod
    def save(
        cls,
        spec: ReportSpec,
        objects: Iterable[Any],
        path: str,
        *,
        include_summary: bool = True,
    ) -> None:
        raise NotImplementedError

    __schema__ = {"spec": ReportSpec}
    __enums__ = {}


# ---------- Vulnerability collector ----------


def collect_vulnerabilities(
    objects: Iterable[Any],
) -> Iterable[Tuple[Vulnerability, str]]:
    """
    Walk arbitrary objects/lists/dicts/BaseModel graphs and yield
    (Vulnerability, context_path) pairs. The traversal skips BaseModel class
    metadata (JSON_ADAPTERS, PARSERS, __schema__, __enums__) and only treats a
    dict as a Vulnerability if it "looks like" one (has core fields).
    """
    seen: Set[int] = set()
    SKIP_ATTRS = {
        "JSON_ADAPTERS",
        "PARSERS",
        "__schema__",
        "__enums__",
        "vulnerabilities",
    }

    def _looks_like_vuln_dict(d: Any) -> bool:
        if not isinstance(d, dict):
            return False
        # require at least a title or a description to avoid class-level dicts
        if "title" in d:
            return True
        # alternatively, a minimal risk block + description is also fine
        if "description" in d and isinstance(
            d.get("risk"), (dict, BaseModel, type(None))
        ):
            return True
        return False

    def coerce_v(node: Any) -> Optional[Vulnerability]:
        if isinstance(node, Vulnerability):
            return node
        if isinstance(node, dict) and _looks_like_vuln_dict(node):
            return Vulnerability.from_dict(node)
        return None

    def _walk(node: Any, path: str) -> Iterator[Tuple[Vulnerability, str]]:
        oid = id(node)
        if oid in seen:
            return
        seen.add(oid)

        # Direct vulnerability / vuln-like dict
        v = coerce_v(node)
        if v is not None:
            yield (v, path)
            return

        # List/Tuple
        if isinstance(node, (list, tuple)):
            for i, item in enumerate(node):
                yield from _walk(item, f"{path}[{i}]")
            return

        # Dict
        if isinstance(node, dict):
            for k, val in node.items():
                # keys in dicts can be non-strings; the path is just for humans
                key_str = str(k)
                yield from _walk(val, f"{path}.{key_str}")
            return

        # BaseModel or general object
        # 1) common convention: attribute named "vulnerabilities"
        if hasattr(node, "vulnerabilities"):
            maybe = getattr(node, "vulnerabilities")
            if isinstance(maybe, (list, tuple)):
                for i, item in enumerate(maybe):
                    vv = coerce_v(item)
                    if vv is not None:
                        yield (vv, f"{path}.vulnerabilities[{i}]")

        # 2) Shallow attribute walk for nested containers/models
        for attr in dir(node):
            if attr.startswith("_") or attr in SKIP_ATTRS:
                continue
            # Avoid binding descriptors/specials; best-effort try/except
            try:
                val = getattr(node, attr)
            except Exception:
                continue
            # Only follow containers and BaseModel instances; skip class-level dicts etc.
            if isinstance(val, (list, tuple, dict, BaseModel)):
                yield from _walk(val, f"{path}.{attr}")

    # Roots
    for obj in objects:
        cls_name = getattr(obj, "__class__", type(obj)).__name__
        name = getattr(obj, "name", None)
        label = f"{cls_name}[name={name}]" if isinstance(name, str) else cls_name
        yield from _walk(obj, label)


def collect_test_runs(
    objects: Iterable[Any],
) -> Iterable[Tuple[TestCaseRun, Optional[TestCase], str]]:
    """
    Yields (TestCaseRun, TestCase, context_path).
    We look for an Operation/Pentest to resolve the TestCase definition.
    """
    seen: Set[int] = set()

    # Pre-calculate a lookup map if the object is an Operation
    tc_lookup: Dict[str, TestCase] = {}
    for obj in objects:
        if hasattr(obj, "iterTestCases"):
            tc_lookup.update({tc.code: tc for tc in obj.iterTestCases()})

    def _walk(
        node: Any, path: str
    ) -> Iterator[Tuple[TestCaseRun, Optional[TestCase], str]]:
        oid = id(node)
        if oid in seen:
            return
        seen.add(oid)

        if isinstance(node, TestCaseRun):
            parent_tc = tc_lookup.get(node.test_case_code)
            yield (node, parent_tc, path)
            return
        if isinstance(node, (list, tuple)):
            for i, item in enumerate(node):
                yield from _walk(item, f"{path}[{i}]")
        elif hasattr(node, "__dict__"):
            # Check for attributes that hold test execution data
            for attr in ["test_runs", "test_plans"]:
                if hasattr(node, attr):
                    yield from _walk(getattr(node, attr), f"{path}.{attr}")

    for obj in objects:
        yield from _walk(obj, obj.__class__.__name__)
