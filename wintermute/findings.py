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

import logging
from typing import Any, Dict, Sequence

from .basemodels import BaseModel

log = logging.getLogger(__name__)


class ReproductionStep(BaseModel):
    """This class holds a reproduction step for vulnerabilities

    This class holds a reproduction step for vulnerabilities, it can contain
    the tool used, action taken, confidence level and arguments passed to the tool.

    Examples:
        >>> import core
        >>> rs = core.ReproductionStep(
        ...     tool="nmap",
        ...     action="scan",
        ...     confidence=5,
        ...     arguments=["-sV", "-script=vuln"],
        ... )
        >>> print(rs.tool)
        nmap
        >>> print(rs.confidence)
        5
        >>> print(rs.arguments)
        ['-sV', '-script=vuln']

    Attributes:
        * title (str): Title of the reproduction step
        * description (str): Description of the reproduction step
        * tool (str): Tool used in the reproduction step
        * action (str): Action taken in the reproduction step
        * confidence (int): Confidence level of the reproduction step (0-10)
        * arguments (array): Array of arguments passed to the tool
        * vulnOutput (str): Output from the vulnerability scan
        * fixOutput (str): Output from the fix attempt
    """

    def __init__(
        self,
        title: str = "",
        description: str = "",
        tool: str | None = None,
        action: str | None = None,
        confidence: int = 0,
        arguments: Sequence[str] | None = None,
        vulnOutput: str | None = None,
        fixOutput: str | None = None,
    ) -> None:
        self.title = title
        self.description = description
        self.tool = tool
        self.action = action
        self.confidence = confidence
        self.arguments: Sequence[str] = arguments or []
        self.vulnOutput = vulnOutput
        self.fixOutput = fixOutput
        pass


class Risk(BaseModel):
    """This class defines and holds the Risks, it inherits from the Vulns

    This class defines the risk for the vulnerability is assigned to, is designed to
    be used by a vulnerability itself

    Examples:
        >>> import core
        >>> r = core.Risk(likelihood="High", impact="High", severity="Critical")
        >>> print(r.severity)
        Critical
        >>> print(r.likelihood)
        High
        >>> print(r.impact)
        High

    Attributes:
        * likelihood (str): Likelihood of the vulnerability
        * impact (str): Impact of the vulnerability
        * severity (str): Severity of the vulnerability
    """

    def __init__(
        self, likelihood: str = "Low", impact: str = "Low", severity: str = "Low"
    ) -> None:
        self.likelihood = likelihood
        self.impact = impact
        self.severity = severity


class Vulnerability(BaseModel):
    """This class holds a vulnerability found

    This class holds a vulnerability found during the operation, it can contain
    reproduction steps and a risk object.

    Examples:
        >>> import core
        >>> v = core.Vulnerability(
        ...     title="CVE-2020-1234", description="Example vuln", cvss=7
        ... )
        >>> print(v.title)
        CVE-2020-1234
        >>> print(v.cvss)
        7
        >>> v.setRisk(likelihood="High", impact="High", severity="Critical")
        >>> print(v.risk.severity)
        Critical

    Attributes:
        * title (str): Title of the vulnerability
        * description (str): Description of the vulnerability
        * threat (str): Threat posed by the vulnerability
        * cvss (int): CVSS score of the vulnerability
        * mitigation (bool): Whether there is a mitigation available
        * fix (bool): Whether there is a fix available
        * fix_desc (str): Description of the fix
        * mitigation_desc (str): Description of the mitigation
        * risk (Risk): Risk object associated with the vulnerability
        * verified (bool): Whether the vulnerability has been verified
        * reproduction_steps (array): Array of ReproductionStep objects detailing how to reproduce the vuln

    """

    __schema__ = {
        "risk": Risk,
        "reproduction_steps": ReproductionStep,
    }

    def __init__(
        self,
        title: str = "",
        description: str = "",
        threat: str = "",
        cvss: int = 0,
        mitigation: bool = True,
        fix: bool = True,
        fix_desc: str = "",
        mitigation_desc: str = "",
        risk: Dict[Any, Any] | Risk = {},
        verified: bool = False,
        reproduction_steps: list[ReproductionStep] | None = None,
    ) -> None:
        self.title = title
        self.description = description
        self.threat = threat
        self.cvss = cvss
        self.mitigation = mitigation  # Boolean
        self.fix = fix  # Boolean
        self.mitigation_desc = mitigation_desc
        self.fix_desc = fix_desc
        self.verified = verified  # If exploited or high confidence this will be true
        self.reproduction_steps = reproduction_steps or []

        if isinstance(risk, Risk):
            self.risk = risk
        elif isinstance(risk, dict):
            self.risk = Risk.from_dict(risk)
        else:
            self.risk = Risk()

    def setRisk(
        self, likelihood: str = "Low", impact: str = "Low", severity: str = "Low"
    ) -> None:
        self.risk = Risk(likelihood=likelihood, impact=impact, severity=severity)
