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

from typing import Any, List, Optional, Protocol

from ..findings import ReproductionStep, Risk, Vulnerability


class SupportsVulns(Protocol):
    """Any object that has a .vulnerabilities: list[Vulnerability].
    

    Examples:
        >>> import wintermute.peripherals
        >>> from wintermute.utils.findings import (
        ...     add_vulnerability,
        ...     get_vulnerability,
        ...     remove_vulnerability,
        ...     add_reproduction_step,
        ...     )
        >>> uart = UART(name="UART0")
        >>> v = add_vulnerability(
        ...     uart,
        ...     title="UART console exposed",
        ...     description="The UART console is exposed and allows access to the system.",
        ...     cvss=7,
        ...     risk={"likelihood": "High", "impact": "High", "severity": "Critical"},
        ... )
        >>> add_reproduction_step(
        ...     uart,
        ...     title="UART console exposed",
        ...     step={
        ...         "title": "Probe pins",
        ...         "description": "Connect to T/RX/GND at 115200 8N1 and observe root prompt.",
        ...         "tool": "USB-UART",
        ...         "action": "connect",
        ...         "confidence": 90,
        ...     },
        ... )
        True
        >>> remove_vulnerability(uart, title="UART console exposed")
        True    
    """

    vulnerabilities: List[Vulnerability]


def add_vulnerability(
    obj: SupportsVulns,
    *,
    title: str,
    description: str,
    threat: str = "",
    cvss: int = 0,
    mitigation: bool = True,
    fix: bool = True,
    fix_desc: str = "",
    mitigation_desc: str = "",
    risk: Optional[dict[Any, Any]] = None,
    verified: bool = False,
) -> Vulnerability:
    v = Vulnerability(
        title=title,
        description=description,
        threat=threat,
        cvss=cvss,
        mitigation=mitigation,
        fix=fix,
        fix_desc=fix_desc,
        mitigation_desc=mitigation_desc,
        verified=verified,
    )
    if risk:
        v.risk = Risk.from_dict(risk)
    obj.vulnerabilities.append(v)
    return v


def get_vulnerability(
    obj: SupportsVulns,
    *,
    uid: Optional[str] = None,
    title: Optional[str] = None,
) -> Optional[Vulnerability]:
    for v in obj.vulnerabilities:
        if uid is not None and getattr(v, "uid", None) == uid:
            return v
        if title is not None and v.title == title:
            return v
    return None


def add_reproduction_step(
    obj: SupportsVulns,
    *,
    uid: Optional[str] = None,
    title: Optional[str] = None,
    step: ReproductionStep | dict[Any, Any],
) -> bool:
    v = get_vulnerability(obj, uid=uid, title=title)
    if not v:
        return False
    v.reproduction_steps.append(
        step if isinstance(step, ReproductionStep) else ReproductionStep.from_dict(step)
    )
    return True


def remove_vulnerability(
    obj: SupportsVulns,
    *,
    uid: Optional[str] = None,
    title: Optional[str] = None,
) -> bool:
    for i, v in enumerate(obj.vulnerabilities):
        if uid is not None and getattr(v, "uid", None) == uid:
            obj.vulnerabilities.pop(i)
            return True
        if title is not None and v.title == title:
            obj.vulnerabilities.pop(i)
            return True
    return False
