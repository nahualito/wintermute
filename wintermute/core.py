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

"""
Core classes for Wintermute
---------------------------

This file contains the core classes used throughout Wintermute, including
Device, Service, User, AWSAccount, Analyst, Operation, and Pentest.
"""

import ipaddress
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from tinydb import TinyDB

from .basemodels import BaseModel, Peripheral, PeripheralType
from .cloud.aws import AWSAccount
from .findings import ReproductionStep, Vulnerability
from .hardware import Architecture, Memory, Processor

__all__ = [
    "Device",
    "Service",
    "Vulnerability",
    "Operation",
    "Pentest",
    "AWSAccount",
    "User",
]

log = logging.getLogger(__name__)


class Service(BaseModel):
    """This class holds the network port objects

    This class holds the network port objects and will allow to track states, versions and vulns.

    Examples:
        >>> import core
        >>> s = core.Service(
        ...     protocol="ipv4",
        ...     app="nginx",
        ...     portNumber=80,
        ...     banner="nginx 1.18",
        ...     transport_layer="HTTP",
        ... )
        >>> s.portNumber
        80
        >>> s.app
        'nginx'
        >>> s.addVulnerability(
        ...     title="CVE-2020-1234", description="Example vuln", cvss=7
        ... )
        >>> len(s.vulnerabilities)
        1
        >>> s.vulnerabilities[0].title
        'CVE-2020-1234'

    Attributes:
        * protocol (str): Transport protocol (ipv4/ipv6)
        * app (str): Application running in the port
        * portNumber (int): port the service is listening on
        * banner (str): Banner of the service
        * transport_layer (str): Application protocol (HTTP, HTTPS, FTP, SSH, etc)
    """

    __schema__ = {
        "vulnerabilities": Vulnerability,
    }

    def __init__(
        self,
        name: str = "",
        protocol: str = "ipv4",
        app: str = "",
        portNumber: int = 0,
        banner: str = "",
        transport_layer: str = "",
        vulnerabilities: list[Vulnerability] | list[dict[str, Any]] | None = None,
    ) -> None:
        self.name = name
        self.protocol = protocol
        self.app = app
        self.portNumber = portNumber
        self.banner = banner
        self.transport_layer = transport_layer
        self.vulnerabilities: list[Vulnerability] = []
        for v in vulnerabilities or []:
            self.vulnerabilities.append(
                Vulnerability.from_dict(v) if isinstance(v, dict) else v
            )
        log.info(
            f"Created Service: {self.app} on port {self.portNumber}/{self.protocol} with {len(self.vulnerabilities)} vulnerabilities"
        )

    def addVulnerability(
        self,
        title: str = "",
        description: str = "",
        threat: str = "",
        cvss: int = 0,
        mitigation: bool = True,
        fix: bool = True,
        fix_desc: str = "",
        mitigation_desc: str = "",
        risk: Dict[Any, Any] = {},
        verified: bool = False,
    ) -> bool:
        v = Vulnerability(
            title=title,
            description=description,
            threat=threat,
            cvss=cvss,
            mitigation=mitigation,
            fix=fix,
            fix_desc=fix_desc,
            mitigation_desc=mitigation_desc,
            risk=risk,
            verified=verified,
        )
        if v not in self.vulnerabilities:
            self.vulnerabilities.append(v)
            log.info(
                f"Added Vulnerability {v.title} to Service {self.app} on port {self.portNumber}/{self.protocol}"
            )
            return True
        log.debug(
            f"Vulnerability {v.title} already exists on Service {self.app} on port {self.portNumber}/{self.protocol}, not adding."
        )
        return False


class Device(BaseModel):
    """This class contains the information about the devices in the operation.

    This class contains the information about the device in the operation,
    including hostname, ip address, mac, OS this class was not designed to
    be called by itself, it should be derived and the inherited classes
    manipulated.

    Examples:
        >>> import core
        >>> d = core.Device("test.foo.bar", "127.0.0.1", "00:00:00:00:00", "Windows")
        >>> print(d.operatingsystem)
        Windows

    Attributes:
        * hostname (str): hostname of the device
        * ipaddr (IPv4Address): IPv4 address of the machine
        * macaddr (str): mac address
        * operatingsystem (str): Operating System (ENUM based on a dictionary)
        * fqdn (str): Fully Qualified Domain name
        * architecture (str): Architecture of the machine (x86, x64, ARM, etc)
        * processor (str): Processor of the machine (Maxis, ARM7, Cortex, etc)
        * services (array): Array of Service objects holding the open services on the machine.
        * peripherals (array): Array of Peripheral objects connected to the machine.
    """

    __schema__ = {
        "services": Service,
        "peripherals": Peripheral,
        "processor": Processor,
        "architecture": Architecture,
        "memory": Memory,
    }

    def __init__(
        self,
        hostname: str = "",
        ipaddr: str
        | ipaddress.IPv4Address
        | ipaddress.IPv6Address
        | None = "127.0.0.1",
        macaddr: str = "",
        operatingsystem: str = "",
        fqdn: str = "",
        architecture: Architecture | None = None,
        processor: Processor | None = None,
        memory: Memory | None = None,
        services: list[Service] | list[dict[str, Any]] | None = None,
        peripherals: list[Peripheral] | list[dict[str, Any]] | None = None,
    ) -> None:
        self.hostname = hostname
        if isinstance(ipaddr, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            self.ipaddr = ipaddr
        else:
            self.ipaddr = ipaddress.ip_address(ipaddr or "127.0.0.1")
        self.macaddr = macaddr
        self.operatingsystem = operatingsystem
        self.fqdn = fqdn
        self.architecture = architecture
        self.processor = processor
        self.memory = memory
        self.services: list[Service] = []
        self.peripherals: list[Peripheral] = []

        for s in services or []:
            self.services.append(Service.from_dict(s) if isinstance(s, dict) else s)

        for p in peripherals or []:
            self.peripherals.append(
                Peripheral.from_dict(p) if isinstance(p, dict) else p
            )
        log.info(
            f"Created Device: {self.hostname} ({self.ipaddr}) with {len(self.services)} services and {len(self.peripherals)} peripherals"
        )

    def addService(
        self,
        protocol: str = "ipv4",
        app: str = "",
        portNumber: int = 0,
        banner: str = "",
        transport_layer: str = "",
        vulnerabilities: list[Vulnerability] = [],
    ) -> bool:
        s = Service(
            protocol=protocol,
            app=app,
            portNumber=portNumber,
            banner=banner,
            transport_layer=transport_layer,
            vulnerabilities=vulnerabilities,
        )
        if s not in self.services:
            self.services.append(s)
            log.info(
                f"Added Service {app} on port {portNumber}/{protocol} to Device {self.hostname}"
            )
            return True
        log.debug(
            f"Service {app} on port {portNumber}/{protocol} already exists on Device {self.hostname}, not adding."
        )
        return False


class User(BaseModel):
    """This class holds the user object.

    This class holds the user object, it can contain multiple desktops
    associated with the user, it can also contain LDAP groups and teams
    the user belongs to.

    Examples:
        >>> import core
        >>> u = core.addUser(
        ...     uid="jsmith", name="John Smith", email="john@example.com", teams=["Red"]
        ... )
        >>> print(u.email)
        john@example.com
        >>> print(u.teams)
        ['Red']

    Attributes:
        * uid (str): Unique ID for the user
        * name (str): Name of the user
        * email (str): Email address of the user
        * dept (str): Department the user belongs to
        * permissions (array): Array of permissions the user has
        * override_reason (str): Reason for overriding permissions
        * desktops (array): Array of Device objects representing the user's desktops
        * ldap_groups (array): Array of LDAP groups the user belongs to
        * teams (array): Array of teams the user belongs to
    """

    __schema__ = {
        "desktops": Device,
    }

    def __init__(
        self,
        uid: str = "",
        name: str = "",
        email: str = "",
        dept: str = "",
        permissions: Sequence[str] | None = None,
        override_reason: str = "",
        desktops: list[Device] | None = None,
        ldap_groups: Sequence[str] | None = None,
        teams: Sequence[str] | None = None,
        cloud_accounts: Sequence[str] | None = None,
    ) -> None:
        self.uid = uid
        self.name = name
        self.email = (
            email if email is not None else (f"{uid}@stubemail.com" if uid else "")
        )
        self.dept = dept
        self.permissions = list(permissions) if permissions else []
        self.override_reason = override_reason
        self.desktops: list[Device] = list(desktops) if desktops else []
        self.ldap_groups: list[str] = list(ldap_groups) if ldap_groups else []
        self.cloud_accounts: list[str] = list(cloud_accounts) if cloud_accounts else []
        self.teams: list[str] = []
        log.debug(
            f"Initializing User: {self.uid} ldap_groups: {ldap_groups} desktops: {desktops} permissions: {permissions}"
        )

        if teams:
            for team in teams:
                if team not in self.teams:
                    self.teams.append(team)
                    log.debug(f"Added team {team} to user {self.uid}")
        log.info(
            f"Created User: {self.uid} with teams: {self.teams} and permissions: {self.permissions} with desktops: {len(self.desktops)} and permissions: {self.permissions}"
        )

    def addDesktop(
        self, hostname: str, ipaddr: str, macaddr: str, operatingsystem: str, fqdn: str
    ) -> bool:
        d = Device(hostname, ipaddr, macaddr, operatingsystem, fqdn)
        if d not in self.desktops:
            self.desktops.append(d)
            log.info(f"Added desktop {hostname} to user {self.uid}")
            return True
        return False


class Analyst(BaseModel):
    """This class contains the information about the analyst for the incident, including name, ID and email.

    This class contains the information about the analysts for the incident, including name, ID and email,
    this class was not designed to be called by itself, it should be called from Incident for it's management

    Examples:
        >>> import core
        >>> r = core.Analyst("Enrique Sanchez", "nahual", "nahual@exploit.ninja")
        >>> r.name
        'Enrique Sanchez'
        >>> r.email
        'nahual@exploit.ninja'
        >>> r.userid
        'nahual'

    Attributes:
        * name (str): Name of the analyst.
        * userid (str): Unique ID (LANID, login, etc) for the Analyst.
        * email (str): Email address for the analyst, is validated for correct format but not delivery.
    """

    def __init__(self, name: str = "", userid: str = "", email: str = "") -> None:
        #: Name of the analyst.
        self.name = name
        #: Unique ID (alias, LANID, login, etc.) for the Analyst.
        self.userid = userid
        #: Email address of the analyst.
        self.email = email if self.isValidEmail(email) else None
        log.info(
            f"Created Analyst: {self.name} with userid: {self.userid} and email: {self.email}"
        )

    def isValidEmail(self, email: str) -> bool:
        """Check that the email has the correct format, we do not check the email is deliverable, left to the user.

        Returns:
            bool: True if it's valid, false if it's incorrect format
        """
        if len(email) > 7:
            if (
                re.search(r"^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$", email)
                is not None
            ):
                return True
        return False

    def isValidName(self, name: str) -> bool:
        """Check the name is not None

        Returns:
            bool: True if the name is valid
        """
        return True if not None else False

    def isValidUserId(self, userid: str) -> bool:
        """Check that the userid is not None"""
        return True if not None else False


# ---------------------------------------------------------------------------
# Test Plans + Test Runs (declarative plans, operational run records)
# ---------------------------------------------------------------------------


class BindKind(str, Enum):
    device = "device"
    peripheral = "peripheral"


class BindCardinality(str, Enum):
    one = "one"
    many = "many"
    at_least_one = "at_least_one"


class ExecutionMode(str, Enum):
    once = "once"
    per_device = "per_device"
    per_binding = "per_binding"


class RunStatus(str, Enum):
    not_run = "not_run"
    in_progress = "in_progress"
    passed = "passed"
    failed = "failed"
    blocked = "blocked"
    not_applicable = "not_applicable"


class ObjectSelector(BaseModel):
    """Declarative selector stored in JSON; resolved against Operation at runtime."""

    __enums__ = {"kind": BindKind, "cardinality": BindCardinality}

    kind: BindKind
    name: str
    cardinality: BindCardinality
    where: dict[str, Any]

    def __init__(
        self,
        kind: BindKind,
        name: str,
        where: Optional[dict[str, Any]] = None,
        cardinality: BindCardinality = BindCardinality.many,
    ) -> None:
        self.kind = kind
        self.name = name
        self.where = where or {}
        self.cardinality = cardinality


class TargetScope(BaseModel):
    __schema__ = {"bindings": ObjectSelector}

    tags: list[str]
    bindings: list[ObjectSelector]

    def __init__(
        self,
        tags: Optional[list[str]] = None,
        bindings: Optional[list[ObjectSelector]] = None,
    ) -> None:
        self.tags = tags or []
        self.bindings = bindings or []


class TestCase(BaseModel):
    """Declarative test case: scope selectors + reproduction steps."""

    __test__ = False
    __schema__ = {"target_scope": TargetScope, "steps": ReproductionStep}
    __enums__ = {"execution_mode": ExecutionMode}

    code: str
    name: str
    description: str

    target_scope: TargetScope
    steps: list[ReproductionStep]

    executed: bool
    execution_mode: ExecutionMode
    execution_binding: str

    def __init__(
        self,
        code: str,
        name: str,
        description: str,
        target_scope: Optional[TargetScope] = None,
        steps: Optional[list[ReproductionStep]] = None,
        executed: bool = False,
        execution_mode: ExecutionMode = ExecutionMode.once,
        execution_binding: str = "",
    ) -> None:
        self.code = code
        self.name = name
        self.description = description
        self.target_scope = target_scope or TargetScope()
        self.steps = steps or []
        self.executed = executed
        self.execution_mode = execution_mode
        self.execution_binding = execution_binding


class TestPlan(BaseModel):
    """A plan can contain test cases and nested plans (HW, Web/API, Network)."""

    __schema__ = {"test_cases": TestCase, "test_plans": "TestPlan"}

    code: str
    name: str
    description: str
    test_cases: list[TestCase]
    test_plans: list["TestPlan"]

    def __init__(
        self,
        code: str,
        name: str,
        description: str,
        test_cases: Optional[list[TestCase]] = None,
        test_plans: Optional[list["TestPlan"]] = None,
    ) -> None:
        self.code = code
        self.name = name
        self.description = description
        self.test_cases = test_cases or []
        self.test_plans = test_plans or []


class BoundObjectRef(BaseModel):
    kind: str
    object_id: str
    alias: str

    def __init__(self, kind: str, object_id: str, alias: str) -> None:
        self.kind = kind
        self.object_id = object_id
        self.alias = alias


class TestCaseRun(BaseModel):
    __test__ = False
    __schema__ = {"bound": BoundObjectRef, "findings": Vulnerability}
    __enums__ = {"status": RunStatus}

    run_id: str
    test_case_code: str
    status: RunStatus

    started_at: datetime | None
    ended_at: datetime | None

    executed_by: str
    notes: str

    bound: list[BoundObjectRef]
    findings: list[Vulnerability]

    def __init__(
        self,
        run_id: str,
        test_case_code: str,
        status: RunStatus = RunStatus.not_run,
        started_at: datetime | None = None,
        ended_at: datetime | None = None,
        executed_by: str = "",
        notes: str = "",
        bound: Optional[list[BoundObjectRef]] = None,
        findings: Optional[list[Vulnerability]] = None,
    ) -> None:
        self.run_id = run_id
        self.test_case_code = test_case_code
        self.status = status
        self.started_at = started_at
        self.ended_at = ended_at
        self.executed_by = executed_by
        self.notes = notes
        self.bound = bound or []
        self.findings = findings or []

    def start(self) -> None:
        if self.started_at is None:
            self.started_at = datetime.now(timezone.utc)

    def finish(self) -> None:
        if self.ended_at is None:
            self.ended_at = datetime.now(timezone.utc)


class Operation(BaseModel):
    """This class contains the information about the operation including devices, analysts and name of the operation.

    This is the top level class to call on operations, while you can call all other classes such as EDR, Devices, etc.
    these classes will not have the automation capabilities added as incident, but they can be called for more
    flexibility on this library.

    Examples:
        >>> from wintermute import core
        >>> op = core.Operation("testOp")
        >>> op.addAnalyst("Alice", "aalice", "alice@example.com")
        True
        >>> op.addDevice(
        ...     "host1", "192.168.1.10", "aa:bb:cc:dd:ee:ff", "Linux", "host1.local"
        ... )
        True
        >>> op.addUser(
        ...     uid="jsmith", name="John Smith", email="john@example.com", teams=["Red"]
        ... )
        True
        >>> op.addAWSAccount(
        ...     accountId="111122223333", name="Prod", description="Prod account"
        ... )
        True
        >>> op.save()

    Attributes:
        * operation_name (str): Name of the operation.
        * uuid (str): Generated UUID for the UUID, based on host ID and current time.
        * analysts (array): Array of analyst objects which contain the information for the people involved.
        * devices (array): Array of device objects involved in the incident.
        * ticket (str): Ticket ID for the pentesting
        * db (TinyDB): database object pointing to the TinyDB
        * start_date (str): Start date of the pentest in the form of MM/DD/YY
        * end_date (str): End date of the pentest in the form of MM/DD/YY
        * users (array): Array of User objects to be held by the operation/pentest (stakeholders, devs, etc)
        * awsaccounts (array): Array of AWSAccount objects to hold AWS accounts involved in the operation
        * operation_id (str): Unique ID for the operation, this is a UUID4 string
        * ticket (str): Ticket ID for the operation
        * start_date (str): Start date of the operation in MM/DD/YYYY format
        * end_date (str): End date of the operation in MM/DD/YYYY format
    """

    __schema__ = {
        "analysts": Analyst,
        "devices": Device,
        "users": User,
        "test_plans": TestPlan,
        "test_runs": TestCaseRun,
    }

    def __init__(
        self,
        operation_name: str = "Wintermute",
        analysts: list[Analyst] | list[dict[str, Any]] | None = None,
        ticket: str = "",
        devices: list[Device] | list[dict[str, Any]] | None = None,
        end_date: str = datetime.today().strftime("%m/%d/%Y"),
        start_date: str = datetime.today().strftime("%m/%d/%Y"),
        users: list[User] | list[dict[str, Any]] | None = None,
        operation_id: str = str(uuid.uuid1()),
        # ADDED cloud_accounts argument
        cloud_accounts: list[Any] | list[dict[str, Any]] | None = None,
        awsaccounts: list[Any] | list[dict[str, Any]] | None = None,
        # ADDED test_plans and test_runs (Fixes IndexError)
        test_plans: list[TestPlan] | list[dict[str, Any]] | None = None,
        test_runs: list[TestCaseRun] | list[dict[str, Any]] | None = None,
        db: str = "",
        **kwargs: Any,
    ) -> None:
        self.operation_name = operation_name
        self._db = TinyDB(f"{operation_name}.json")
        self.operation_id = operation_id
        self.start_date = start_date
        self.end_date = end_date
        self.ticket = ticket or None

        self.analysts: list[Analyst] = []
        self.devices: list[Device] = []
        self.users: list[User] = []
        self.cloud_accounts: list[Any] = []

        # Logic using cloud_type
        for acc in cloud_accounts or []:
            c_type = None
            if isinstance(acc, dict):
                c_type = acc.get("cloud_type")
            else:
                c_type = getattr(acc, "cloud_type", None)

            if c_type == "AWS":
                self.cloud_accounts.append(
                    AWSAccount.from_dict(acc) if isinstance(acc, dict) else acc
                )
            else:
                self.cloud_accounts.append(acc)

        # Legacy AWS Accounts (Force cloud_type="AWS")
        for acc in awsaccounts or []:
            if isinstance(acc, dict):
                acc["cloud_type"] = "AWS"
                self.cloud_accounts.append(AWSAccount.from_dict(acc))
            else:
                if not hasattr(acc, "cloud_type"):
                    acc.cloud_type = "AWS"
                self.cloud_accounts.append(acc)

        for a in analysts or []:
            self.analysts.append(Analyst.from_dict(a) if isinstance(a, dict) else a)
        for d in devices or []:
            self.devices.append(Device.from_dict(d) if isinstance(d, dict) else d)
        for u in users or []:
            self.users.append(User.from_dict(u) if isinstance(u, dict) else u)

        # Rehydration for TestPlans (Fixes missing args issue)
        self.test_plans: list[TestPlan] = []
        for tp in test_plans or []:
            self.test_plans.append(
                TestPlan.from_dict(tp) if isinstance(tp, dict) else tp
            )

        # Rehydration for TestRuns
        self.test_runs: list[TestCaseRun] = []
        for tr in test_runs or []:
            self.test_runs.append(
                TestCaseRun.from_dict(tr) if isinstance(tr, dict) else tr
            )

        log.info(
            f"Created Operation: {self.operation_name} with ID: {self.operation_id}"
        )

    def addTestPlan(self, plan: TestPlan | dict[str, Any]) -> bool:
        """Attach a TestPlan to this Operation. Supports multiple plans per operation."""
        tp = plan if isinstance(plan, TestPlan) else TestPlan.from_dict(plan)
        if tp not in self.test_plans:
            self.test_plans.append(tp)
            log.info(f"Added TestPlan {tp.code} to Operation {self.operation_name}")
            return True
        return False

    def iterTestCases(self) -> list[TestCase]:
        """Return all test cases across all attached plans (including nested)."""
        out: list[TestCase] = []

        def walk(p: TestPlan) -> None:
            out.extend(p.test_cases)
            for sub in p.test_plans:
                walk(sub)

        for p in self.test_plans:
            walk(p)
        return out

    def resolveBindings(self, tc: TestCase) -> dict[str, list[Any]]:
        """Resolve tc.target_scope.bindings against current Operation devices/peripherals."""
        resolved: dict[str, list[Any]] = {}

        # Devices
        for sel in tc.target_scope.bindings:
            if sel.kind != BindKind.device:
                continue
            where = sel.where or {}
            host = str(where.get("hostname", "")).strip()
            fqdn = str(where.get("fqdn", "")).strip()

            matches: list[Device] = []
            for d in self.devices:
                if host and getattr(d, "hostname", "") != host:
                    continue
                if fqdn and getattr(d, "fqdn", "") != fqdn:
                    continue
                matches.append(d)

            resolved[sel.name] = matches
            if sel.cardinality == BindCardinality.one and len(matches) != 1:
                raise ValueError(
                    f"{tc.code}: binding '{sel.name}' expected 1 device, got {len(matches)}"
                )
            if sel.cardinality == BindCardinality.at_least_one and len(matches) < 1:
                raise ValueError(
                    f"{tc.code}: binding '{sel.name}' expected >=1 device, got 0"
                )

        # Peripherals
        for sel in tc.target_scope.bindings:
            if sel.kind != BindKind.peripheral:
                continue
            where = sel.where or {}

            dev_alias = where.get("device")
            devs: list[Device]
            if isinstance(dev_alias, str) and dev_alias in resolved:
                devs = [x for x in resolved[dev_alias] if isinstance(x, Device)]
            else:
                devs = list(self.devices)

            # pType matching by NAME ("UART") or int
            want_ptype: PeripheralType | None = None
            ptype = where.get("pType")
            if isinstance(ptype, PeripheralType):
                want_ptype = ptype
            elif isinstance(ptype, str):
                try:
                    want_ptype = PeripheralType[ptype]
                except KeyError:
                    want_ptype = None
            elif isinstance(ptype, int):
                try:
                    want_ptype = PeripheralType(ptype)
                except ValueError:
                    want_ptype = None

            name = str(where.get("name", "")).strip()

            matches_p: list[Peripheral] = []
            for d in devs:
                for p in getattr(d, "peripherals", []):
                    if name and getattr(p, "name", "") != name:
                        continue
                    if (
                        want_ptype is not None
                        and getattr(p, "pType", None) != want_ptype
                    ):
                        continue
                    matches_p.append(p)

            resolved[sel.name] = matches_p
            if sel.cardinality == BindCardinality.one and len(matches_p) != 1:
                raise ValueError(
                    f"{tc.code}: binding '{sel.name}' expected 1 peripheral, got {len(matches_p)}"
                )
            if sel.cardinality == BindCardinality.at_least_one and len(matches_p) < 1:
                known = [d.hostname for d in self.devices]
                raise ValueError(
                    f"{tc.code}: binding '{sel.name}' expected >=1 peripheral, got 0"
                    f"where={sel.where!r}; known_hostnames={known!r}"
                )

        return resolved

    def createRunsForTestCase(self, tc: TestCase) -> list[TestCaseRun]:
        """Create 1..N TestCaseRun objects for a test case based on tc.execution_mode."""
        resolved = self.resolveBindings(tc)
        runs: list[TestCaseRun] = []

        def device_object_id(d: Device) -> str:
            # No code/id on Device in current model; use hostname/fqdn for now.
            return str(getattr(d, "hostname", "")) or str(getattr(d, "fqdn", ""))

        def find_parent_device(per: Peripheral) -> Device | None:
            for d in self.devices:
                if per in getattr(d, "peripherals", []):
                    return d
            return None

        def peripheral_object_id(p: Peripheral, parent: Device | None) -> str:
            if parent is not None:
                return f"{device_object_id(parent)}:{getattr(p, 'name', '')}"
            return str(getattr(p, "name", ""))

        if tc.execution_mode == ExecutionMode.once:
            runs.append(TestCaseRun(run_id=f"{tc.code}:1", test_case_code=tc.code))
            log.info(f"Created 1 TestCaseRun for TestCase {tc.code} using once mode")
            return runs

        if tc.execution_mode == ExecutionMode.per_device:
            # If any device binding exists, use its matches; else all devices.
            devs: list[Device] = []
            for sel in tc.target_scope.bindings:
                if sel.kind == BindKind.device:
                    devs = [
                        x for x in resolved.get(sel.name, []) if isinstance(x, Device)
                    ]
                    break
            if not devs:
                devs = list(self.devices)

            for i, d in enumerate(devs, 1):
                runs.append(
                    TestCaseRun(
                        run_id=f"{tc.code}:dev{i}",
                        test_case_code=tc.code,
                        bound=[
                            BoundObjectRef(
                                kind="device",
                                object_id=device_object_id(d),
                                alias="dut",
                            )
                        ],
                    )
                )
                log.debug(
                    f"Created TestCaseRun {tc.code}:dev{i} for Device {d.hostname}"
                )
            log.info(
                f"Created {len(devs)} TestCaseRuns for TestCase {tc.code} using per_device mode"
            )
            return runs

        if tc.execution_mode == ExecutionMode.per_binding:
            alias = tc.execution_binding.strip()
            objs = resolved.get(alias, [])
            for i, obj in enumerate(objs, 1):
                if isinstance(obj, Peripheral):
                    parent = find_parent_device(obj)
                    runs.append(
                        TestCaseRun(
                            run_id=f"{tc.code}:{alias}{i}",
                            test_case_code=tc.code,
                            bound=[
                                BoundObjectRef(
                                    kind="peripheral",
                                    object_id=peripheral_object_id(obj, parent),
                                    alias=alias,
                                )
                            ],
                        )
                    )
                elif isinstance(obj, Device):
                    runs.append(
                        TestCaseRun(
                            run_id=f"{tc.code}:{alias}{i}",
                            test_case_code=tc.code,
                            bound=[
                                BoundObjectRef(
                                    kind="device",
                                    object_id=device_object_id(obj),
                                    alias=alias,
                                )
                            ],
                        )
                    )
                log.debug(
                    f"Created TestCaseRun {tc.code}:{alias}{i} for {alias} object"
                )
            log.info(
                f"Created {len(objs)} TestCaseRuns for TestCase {tc.code} using binding '{alias}'"
            )
            return runs
        log.warning(
            f"No TestCaseRuns created for TestCase {tc.code}, unknown execution_mode {tc.execution_mode}"
        )
        return runs

    def generateTestRuns(self, *, replace: bool = False) -> list[TestCaseRun]:
        """Generate runs for every test case across all attached plans."""
        if replace:
            self.test_runs = []
        created: list[TestCaseRun] = []
        existing = {r.run_id for r in self.test_runs}
        for tc in self.iterTestCases():
            for r in self.createRunsForTestCase(tc):
                if r.run_id not in existing:
                    self.test_runs.append(r)
                    existing.add(r.run_id)
                    created.append(r)
        log.info(
            f"Generated {len(created)} new TestCaseRuns for Operation {self.operation_name}"
        )
        return created

    def statusReport(self, start: datetime, end: datetime) -> dict[str, Any]:
        """Stats for runs whose started_at/ended_at fall within [start, end)."""
        total = 0
        by_status: dict[str, int] = {}

        for r in self.test_runs:
            ts = r.started_at or r.ended_at
            if ts is None:
                continue
            if not (start <= ts < end):
                continue
            total += 1
            k = r.status.name
            by_status[k] = by_status.get(k, 0) + 1

        log.info(
            f"Generated status report for Operation {self.operation_name} from {start} to {end}: total_runs={total}, by_status={by_status}"
        )
        return {
            "start": start.isoformat().replace("+00:00", "Z")
            if start.tzinfo
            else start.isoformat(),
            "end": end.isoformat().replace("+00:00", "Z")
            if end.tzinfo
            else end.isoformat(),
            "total_runs": total,
            "by_status": by_status,
        }

    @property
    def dbOperation(self) -> TinyDB:
        return self._db

    @dbOperation.setter
    def dbOperation(self, value: str) -> None:
        if value is not None:
            self.operation_name = value
            self._db = TinyDB(f"{value}.json")

    def addAnalyst(self, name: str, userid: str, email: str) -> bool:
        """Add an analyst to the operation"""
        a = Analyst(name, userid, email)
        if a not in self.analysts:
            self.analysts.append(a)
            log.info(
                f"Added Analyst {name} with userid {userid} to Operation {self.operation_name}"
            )
            return True
        log.warning(
            f"Analyst {name} with userid {userid} already exists in Operation {self.operation_name}, not adding."
        )
        return False

    def delAnalyst(self, userid: str) -> bool:
        """Delete an analyst from the operation by userid"""
        for a in self.analysts:
            if a.userid == userid:
                self.analysts.remove(a)
                log.info(
                    f"Deleted Analyst with userid {userid} from Operation {self.operation_name}"
                )
                return True
        log.warning(
            f"Analyst with userid {userid} not found in Operation {self.operation_name}, cannot delete."
        )
        return False

    def getDeviceByHostname(self, hostname: str) -> Optional[Device]:
        for d in self.devices:
            if d.hostname == hostname:
                return d
        return None

    def addDevice(
        self,
        hostname: str,
        ipaddr: str = "127.0.0.1",
        macaddr: str = "",
        operatingsystem: str = "",
        fqdn: str = "",
        *,
        ipAddress: Optional[str] = None,
        macAddress: Optional[str] = None,
        os: Optional[str] = None,
    ) -> bool:
        """Add a device to the operation (supports legacy keyword aliases)."""

        # legacy aliases override
        if ipAddress is not None:
            ipaddr = ipAddress
        if macAddress is not None:
            macaddr = macAddress
        if os is not None:
            operatingsystem = os

        d = Device(hostname, ipaddr, macaddr, operatingsystem, fqdn)
        log.debug(
            f"Attempting to add Device {hostname} ({ipaddr}) to Operation {self.operation_name}"
        )
        if d not in self.devices:
            self.devices.append(d)
            log.info(
                f"Added Device {hostname} ({ipaddr}) to Operation {self.operation_name}"
            )
            return True
        log.warning(
            f"Device {hostname} ({ipaddr}) already exists in Operation {self.operation_name}, not adding."
        )
        return False

    def delDevice(self, hostname: str) -> bool:
        """Delete a device from the operation by hostname"""
        for d in self.devices:
            if d.hostname == hostname:
                self.devices.remove(d)
                log.info(
                    f"Deleted Device {hostname} from Operation {self.operation_name}"
                )
                return True
        log.warning(
            f"Device {hostname} not found in Operation {self.operation_name}, cannot delete."
        )
        return False

    def addUser(
        self,
        uid: str,
        name: str,
        email: str,
        teams: list[str],
        dept: str = "",
        permissions: list[str] | None = None,
        override_reason: str = "",
        desktops: list[Device] | None = None,
        ldap_groups: list[str] | None = None,
        cloud_accounts: list[str] | None = None,
    ) -> bool:
        """Add a user to the operation"""
        u = User(
            uid=uid,
            name=name,
            email=email,
            teams=teams,
            dept=dept,
            permissions=permissions or [],
            override_reason=override_reason,
            desktops=desktops or [],
            ldap_groups=ldap_groups or [],
            cloud_accounts=cloud_accounts or [],
        )
        log.debug(f"Attempting to add User {uid} to Operation {self.operation_name}")
        if u not in self.users:
            self.users.append(u)
            log.info(f"Added User {uid} to Operation {self.operation_name}")
            return True
        log.warning(
            f"User {uid} already exists in Operation {self.operation_name}, not adding."
        )
        return False

    def delUser(self, uid: str) -> bool:
        """Delete a user from the operation by uid"""
        for u in self.users:
            if u.uid == uid:
                self.users.remove(u)
                log.info(f"Deleted User {uid} from Operation {self.operation_name}")
                return True
        log.warning(
            f"User {uid} not found in Operation {self.operation_name}, cannot delete."
        )
        return False

    # Helper to merge lists without duplicates
    def _merge_lists(self, target_list: list[Any], source_list: list[Any]) -> None:
        """Appends items from source_list to target_list if they don't already exist."""
        if not source_list:
            return
        for item in source_list:
            if item not in target_list:
                target_list.append(item)

    def addCloudAccount(
        self,
        name: str,
        cloud_type: str = "AWS",
        description: str = "",
        *,
        # Common generic args
        account_id: str | None = None,
        tags: Dict[str, str] | None = None,
        # Data to append/merge
        users: Optional[List[Any]] = None,
        roles: Optional[List[Any]] = None,
        services: Optional[List[Any]] = None,
        vulnerabilities: Optional[List[Any]] = None,
        # Catch-all for provider specific args (e.g. partition, arn for AWS)
        **kwargs: Any,
    ) -> bool:
        """
        Adds or Updates a Cloud Account.
        If the account exists, it appends the provided users/services/roles.
        """

        # 1. Determine the Class based on type
        TargetClass = None
        if cloud_type.upper() == "AWS":
            TargetClass = AWSAccount
        # elif cloud_type.upper() == "GCP":
        #     TargetClass = GCPAccount
        else:
            log.error(f"Unsupported Cloud Type: {cloud_type}")
            return False

        # 2. Check if account already exists (by account_id or name)
        existing_acc = None
        for acc in self.cloud_accounts:
            # Check type match first
            if not isinstance(acc, TargetClass):
                continue

            # Match by ID if present, otherwise by Name
            if account_id and getattr(acc, "account_id", None) == account_id:
                existing_acc = acc
                break
            elif acc.name == name:
                existing_acc = acc
                break

        # 3. Update Existing Account
        if existing_acc:
            log.info(f"Updating existing {cloud_type} account: {name}")

            # Update simple fields if they are not empty
            if description:
                existing_acc.description = description
            if tags and hasattr(existing_acc, "tags"):
                if existing_acc.tags is None:
                    existing_acc.tags = {}
                existing_acc.tags.update(tags)

            # Merge Lists (Append Only)
            # This assumes the underlying classes (AWSUser, etc.) have proper __eq__ checks
            # or rely on object identity if they are reused.
            if hasattr(existing_acc, "users") and users:
                self._merge_lists(existing_acc.users, users)

            if hasattr(existing_acc, "roles") and roles:  # Generic roles
                self._merge_lists(existing_acc.roles, roles)

            if (
                hasattr(existing_acc, "iamroles") and "iamroles" in kwargs
            ):  # AWS Specific
                self._merge_lists(existing_acc.iamroles, kwargs["iamroles"])

            if hasattr(existing_acc, "services") and services:
                self._merge_lists(existing_acc.services, services)

            if hasattr(existing_acc, "vulnerabilities") and vulnerabilities:
                self._merge_lists(existing_acc.vulnerabilities, vulnerabilities)

            return True

        # 4. Create New Account
        else:
            log.info(f"Creating new {cloud_type} account: {name}")

            # Construct arguments for the specific class
            # We filter kwargs to ensure we don't pass 'type' if the class doesn't want it,
            # but usually passing **kwargs to init is fine if the class handles it.
            try:
                if cloud_type.upper() == "AWS":
                    # AWSAccount specific signature mapping
                    new_acc = AWSAccount(
                        name=name,
                        description=description,
                        account_id=account_id,
                        tags=tags,
                        users=users,
                        services=services,
                        vulnerabilities=vulnerabilities,
                        roles=roles,
                        **kwargs,  # Passes arn, partition, iamusers, etc.
                    )
                else:
                    # Generic Fallback
                    new_acc = TargetClass(
                        name=name,
                        description=description,
                        account_id=account_id,
                        **kwargs,
                    )

                self.cloud_accounts.append(new_acc)
                return True
            except Exception as e:
                log.error(f"Failed to create cloud account: {e}")
                return False

    def delCloudAccount(self, id_or_name: str) -> bool:
        """Delete a Cloud Account by account_id or name."""
        for acc in self.cloud_accounts:
            # Check ID
            if getattr(acc, "account_id", None) == id_or_name:
                self.cloud_accounts.remove(acc)
                return True
            # Check Name
            if getattr(acc, "name", None) == id_or_name:
                self.cloud_accounts.remove(acc)
                return True
        return False

    # Alias for backward compatibility
    def addAWSAccount(self, name: str, description: str = "", **kwargs: Any) -> bool:
        return self.addCloudAccount(
            name=name, cloud_type="AWS", description=description, **kwargs
        )

    def delAWSAccount(self, accountId: str) -> bool:
        return self.delCloudAccount(accountId)

    @property
    def awsaccounts(self) -> list[AWSAccount]:
        """Dynamic property to maintain backward compatibility for accessing AWS accounts."""
        return [acc for acc in self.cloud_accounts if isinstance(acc, AWSAccount)]

    def save(self) -> None:
        """Save the operation to the TinyDB database"""
        db = TinyDB(f"{self.operation_name}.json")
        db.drop_tables()
        db.insert(self.to_dict())
        db.close()
        log.info(f"Saved Operation {self.operation_name} to database")

    def load(self) -> None:
        """Load the operation from the TinyDB database"""
        db = TinyDB(f"{self.operation_name}.json")
        saved = db.all()[0]
        db.close()
        loaded = Operation.from_dict(saved)
        self.__dict__.update(loaded.__dict__)
        log.info(f"Loaded Operation {self.operation_name} from database")


class Pentest(Operation):
    """This class contains the information about the pentest including devices, analysts and name of the pentest.

    This class inherits from the Operation class (The main and original class) extending things such as the Application Name,
    the application id, the classification for the data in the app, users that hold the pentest, stakeholders, etc.

    Examples:
        >>> from wintermute import core
        >>> pt = core.Pentest("testPentest")
        >>> pt.addAnalyst("Alice", "aalice", "alice@example.com")
        True
        >>> pt.addDevice(
        ...     "host1", "192.168.1.10", "aa:bb:cc:dd:ee:ff", "Linux", "host1.local"
        ... )
        True
        >>> pt.addUser(
        ...     uid="jsmith", name="John Smith", email="john@example.com", teams=["Red"]
        ... )
        True
        >>> pt.addAWSAccount(
        ...     accountId="111122223333", name="Prod", description="Prod account"
        ... )
        True
        >>> pt.save()

    Attributes:
        * ApplicationName (str): Name of the application (default is 'DefaultApp')
        * dataClassification (str): Data classification for the application (default is 'Public')
    """

    def __init__(
        self,
        name: str = "DefaultPentest",
        analysts: list[Analyst] = [],
        quipId: str = "",
        ticket: str = "",
        dataClassification: str = "",
        testEnvironment: str = "",
        ApplicationName: str = "DefaultApp",
        db: TinyDB = TinyDB("Wintermute.json"),
        devices: list[Device] = [],
        start_date: str = datetime.today().strftime("%m/%d/%Y"),
        end_date: str = datetime.today().strftime("%m/%d/%Y"),
        operation_name: str = "",
        users: list[User] = [],
        operation_id: str = str(uuid.uuid1()),
        awsaccounts: list[AWSAccount] = [],
        designDocs: str = "",
        devEmailID: str = "",
        serviceTeamTPM: User = User(),
        devPoc: User = User(),
        devTeamManager: User = User(),
    ) -> None:
        """Init of the pentest class

        This class takes all the arguments for every single self.__dict__ to be able to quickly and easily load from json
        into a full Pentest class with one line instead of statically parsing.

        Args:
            name (str): Name for the Pentest (defaul is DefaultPentest)
            analysts (array): array of Analyst objects or json with the analysts to later be parsed
            ticket (str): Ticket ID for the pentesting
            ApplicationName (str): Name of the application (default is 'DefaultApp')
            dataClassification (str): Data classification for the application (default is 'Public')
            db (TinyDB): database object pointing to the TinyDB
            devices (array): Array of devices that are into the pentest
            start_date (str): Start date of the pentest in the form of MM/DD/YY
            end_date (str): End date of the pentest in the form of MM/DD/YY
            operation_name (str): Name for the pentesting/operation database to hold (default is 'DefaultPentest')
            users (array): Array of User objects to be held by the operation/pentest (stakeholders, devs, etc)
            uuid (str): UUID created for the operation/pentest to be unique in case of multiple pentests with same name/phases
        """
        super().__init__(
            operation_name=name,
            analysts=analysts,
            ticket=ticket,
            devices=devices,
            awsaccounts=awsaccounts,
        )
        self.ApplicationName = ApplicationName
        self.dataClassification = (
            dataClassification  # Public, Confidential, Highly Confidential, Critical
        )
        self.testEnvironment = testEnvironment
        self.devPoc = devPoc
        self.devTeamManager = devTeamManager
        self.serviceTeamTPM = serviceTeamTPM
        self.devEmailID = devEmailID
        self.designDocs = designDocs
        self.quipId = quipId
        # self.loadPentest()
        log.info(
            f"Created Pentest: {self.operation_name} with ApplicationName: {self.ApplicationName} and dataClassification: {self.dataClassification}"
        )

    def loadPentest(self) -> None:
        """Load the pentest from the TinyDB database"""
        f = open(f"{self.operation_name}.json")
        savedData = json.load(f)
        # First record, we shouldn't have more than one anyway, if so .. we shall revisit this
        print(savedData)
        self.__init__(**savedData["_default"]["1"])  # type: ignore[misc]
        log.info(f"Loaded Pentest {self.operation_name} from database")
