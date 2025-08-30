# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use, line-too-long

"""
Core classes for OnoSendai
---------------------------

This file contains the core classes for the onoSendai deck, these are not going to be exported
to the deck, they are for internal deck use.
"""

import inspect
import ipaddress
import json
import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, Self, Sequence, Type

from tinydb import TinyDB


class BaseModel:
    """Base class for all models to provide common functionality.

    This class provides common functionality for all models, including serialization
    to/from dict, equality comparison, and hashing.

    Examples:
        >>> import core
        >>> r = core.Risk(likelihood="High", impact="High", severity="Critical")
        >>> d = r.to_dict()
        >>> d["severity"]
        'Critical'
        >>> r2 = core.Risk.from_dict(d)
        >>> r == r2
        True

    Attributes:
        * __schema__ (dict): Schema defining sub-objects for serialization/deserialization
    """

    __schema__: dict[str, Any] = {}

    JSON_ADAPTERS: Dict[Type[Any], Callable[[Any], Any]] = {
        ipaddress.IPv4Address: str,
        ipaddress.IPv6Address: str,
    }

    @staticmethod
    def _jsonify(value: Any) -> Any:
        """Default recursive serializer used by to_dict()."""
        if isinstance(value, BaseModel):
            return value.to_dict()
        if isinstance(value, list):
            return [BaseModel._jsonify(v) for v in value]
        if isinstance(value, Enum):
            return value.name
        # Built-in adapters
        for typ, adapter in BaseModel.JSON_ADAPTERS.items():
            if isinstance(value, typ):
                return adapter(value)
        # Let subclasses try custom conversions
        extra = BaseModel._jsonify_extra(value)
        if extra is not None:
            return extra
        return value

    @staticmethod
    def _jsonify_extra(value: Any) -> Any:
        """Hook for subclasses to override when they need custom conversions.
        Return None to indicate 'not handled'."""
        return None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in self.__dict__.items():
            if k.startswith("_"):
                continue  # skip private/internal fields (e.g., DB handles)
            out[k] = BaseModel._jsonify(v)
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict for {cls.__name__}, got {type(data)}")

        # 1) Normalize nested fields declared in __schema__ (dicts -> objects, lists -> list[objects])
        normalized: dict[str, Any] = {}
        schema = getattr(cls, "__schema__", {})

        for key, val in data.items():
            if key in schema:
                subcls = schema[key]
                if isinstance(val, list):
                    out_list = []
                    for v in val:
                        if isinstance(v, dict):
                            out_list.append(subcls.from_dict(v))
                        elif isinstance(v, subcls):
                            out_list.append(v)
                        else:
                            raise TypeError(
                                f"Unexpected type in list for {key}: {type(v)}"
                            )
                    normalized[key] = out_list
                elif isinstance(val, dict):
                    normalized[key] = subcls.from_dict(val)
                elif isinstance(val, subcls):
                    normalized[key] = val
                else:
                    raise TypeError(f"Unexpected type for {key}: {type(val)}")
            else:
                normalized[key] = val

        # 2) Only pass kwargs that the constructor actually accepts
        sig = inspect.signature(cls)
        accepted_names = {
            p.name
            for p in sig.parameters.values()
            if p.kind
            in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
        }
        ctor_kwargs = {k: v for k, v in normalized.items() if k in accepted_names}

        # 3) Construct
        obj = cls(**ctor_kwargs)

        # 4) Set any remaining fields (derived attrs like tx/rx/gnd, mosi/miso/etc.)
        for k, v in normalized.items():
            if k not in ctor_kwargs:
                setattr(obj, k, v)

        return obj

    def __eq__(self, other: object) -> bool:
        return isinstance(other, self.__class__) and self.to_dict() == other.to_dict()

    def __hash__(self) -> int:
        return hash(json.dumps(self.to_dict(), sort_keys=True))


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
        * tool (str): Tool used in the reproduction step
        * action (str): Action taken in the reproduction step
        * confidence (int): Confidence level of the reproduction step (0-10)
        * arguments (array): Array of arguments passed to the tool
        * vulnOutput (str): Output from the vulnerability scan
        * fixOutput (str): Output from the fix attempt
    """

    def __init__(self) -> None:
        self.tool = None
        self.action = None
        self.confidence = 0
        self.arguments: Sequence[str] = []
        self.vulnOutput = None
        self.fixOutput = None
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
        protocol: str = "ipv4",
        app: str = "",
        portNumber: int = 0,
        banner: str = "",
        transport_layer: str = "",
        vulnerabilities: list[Vulnerability] | list[dict[str, Any]] | None = None,
    ) -> None:
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
            return True
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
        * services (array): Array of Service objects holding the open services on the machine.
    """

    __schema__ = {
        "services": Service,
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
        services: list[Service] | list[dict[str, Any]] | None = None,
    ) -> None:
        self.hostname = hostname
        if isinstance(ipaddr, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            self.ipaddr = ipaddr
        else:
            self.ipaddr = ipaddress.ip_address(ipaddr or "127.0.0.1")
        self.macaddr = macaddr
        self.operatingsystem = operatingsystem
        self.fqdn = fqdn
        self.services: list[Service] = []
        for s in services or []:
            self.services.append(Service.from_dict(s) if isinstance(s, dict) else s)

    def addService(
        self,
        protocol: str = "ipv4",
        app: str = "",
        portNumber: int = 0,
        banner: str = "",
        transport_layer: str = "",
        vulnerabilities: list[Vulnerability] = [],
    ) -> None:
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
        pass


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
        self.teams: list[str] = []

        if teams:
            for team in teams:
                if team not in self.teams:
                    self.teams.append(team)

    def addDesktop(
        self, hostname: str, ipaddr: str, macaddr: str, operatingsystem: str, fqdn: str
    ) -> bool:
        d = Device(hostname, ipaddr, macaddr, operatingsystem, fqdn)
        if d not in self.desktops:
            self.desktops.append(d)
            return True
        return False


class AWSAccount(BaseModel):
    """This class represents an AWS Account that may contain users and vulnerabilities.

    This class represents an AWS Account that may contain users and vulnerabilities,
    this class was not designed to be called by itself, it should be called from
    Operation for it's management

    Examples:
        >>> import core
        >>> r = core.AWSAccount(
        ...     "111122223333", "Prod Account", "This is the prod account"
        ... )
        >>> r.accountId
        '111122223333'
        >>> r.name
        'Prod Account'
        >>> r.description
        'This is the prod account'

    Attributes:
        * accountId (str): AWS Account ID
        * name (str): Name of the AWS Account
        * description (str): Description of the AWS Account
        * vulnerabilities (array): Array of Vulnerability objects associated with the AWS Account
        * users (array): Array of User objects associated with the AWS Account
    """

    __schema__ = {
        "vulnerabilities": Vulnerability,
        "users": User,
    }

    def __init__(
        self,
        accountId: str,
        name: str,
        description: str = "",
        vulnerabilities: list[Vulnerability] | None = None,
        users: list[User] | None = None,
    ):
        self.accountId = accountId
        self.name = name
        self.description = description

        # Rehydrate vulnerabilities
        self.vulnerabilities: list[Vulnerability] = []
        if vulnerabilities:
            for v in vulnerabilities:
                if isinstance(v, dict):
                    self.vulnerabilities.append(Vulnerability.from_dict(v))
                elif isinstance(v, Vulnerability):
                    self.vulnerabilities.append(v)

        # Rehydrate users
        self.users: list[User] = []
        if users:
            for u in users:
                if isinstance(u, dict):
                    self.users.append(User.from_dict(u))
                elif isinstance(u, User):
                    self.users.append(u)

    def addVulnerability(
        self,
        title: str,
        description: str,
        threat: str = "",
        cvss: int = 0,
        mitigation: bool = True,
        fix: bool = True,
        fix_desc: str = "",
        mitigation_desc: str = "",
        risk: dict[str, str] | None = None,
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
            verified=verified,
        )
        if risk:
            v.setRisk(**risk)
        if v not in self.vulnerabilities:
            self.vulnerabilities.append(v)
            return True
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
    ) -> bool:
        u = User(
            uid=uid,
            name=name,
            email=email,
            teams=teams,
            dept=dept,
            permissions=permissions or [],
            override_reason=override_reason,
        )
        if u not in self.users:
            self.users.append(u)
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

    """

    __schema__ = {
        "analysts": Analyst,
        "devices": Device,
        "users": User,
        "awsaccounts": AWSAccount,
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
        awsaccounts: list[AWSAccount] | list[dict[str, Any]] | None = None,
        db: str = "",
        **kwargs: Any,  # absorb unknown keys safely
    ) -> None:
        self.operation_name = operation_name
        self._db = TinyDB(f"{operation_name}.json")  # private so to_dict skips it
        self.operation_id = operation_id
        self.start_date = start_date
        self.end_date = end_date
        self.ticket = ticket or None

        # fresh lists, then append rehydrated items
        self.analysts: list[Analyst] = []
        self.devices: list[Device] = []
        self.users: list[User] = []
        self.awsaccounts: list[AWSAccount] = []

        for a in analysts or []:
            self.analysts.append(Analyst.from_dict(a) if isinstance(a, dict) else a)
        for d in devices or []:
            self.devices.append(Device.from_dict(d) if isinstance(d, dict) else d)
        for u in users or []:
            self.users.append(User.from_dict(u) if isinstance(u, dict) else u)
        for acc in awsaccounts or []:
            self.awsaccounts.append(
                AWSAccount.from_dict(acc) if isinstance(acc, dict) else acc
            )

    @property
    def dbOperation(self) -> TinyDB:
        return self.db

    @dbOperation.setter
    def dbOperation(self, value: str) -> None:
        if value is not None:
            self.operation_name = value
            self.db = TinyDB(f"{value}.json")

    def addAnalyst(self, name: str, userid: str, email: str) -> bool:
        """Add an analyst to the operation"""
        a = Analyst(name, userid, email)
        if a not in self.analysts:
            self.analysts.append(a)
            return True
        return False

    def addDevice(
        self, hostname: str, ipaddr: str, macaddr: str, operatingsystem: str, fqdn: str
    ) -> bool:
        """Add a device to the operation"""
        d = Device(hostname, ipaddr, macaddr, operatingsystem, fqdn)
        if d not in self.devices:
            self.devices.append(d)
            return True
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
        )
        if u not in self.users:
            self.users.append(u)
            return True
        return False

    def addAWSAccount(self, accountId: str, name: str, description: str = "") -> bool:
        """Add an AWS Account to the operation"""
        a = AWSAccount(accountId, name, description)
        if a not in self.awsaccounts:
            self.awsaccounts.append(a)
            return True
        return False

    def save(self) -> None:
        """Save the operation to the TinyDB database"""
        db = TinyDB(f"{self.operation_name}.json")
        db.drop_tables()
        db.insert(self.to_dict())
        db.close()

    def load(self) -> None:
        """Load the operation from the TinyDB database"""
        db = TinyDB(f"{self.operation_name}.json")
        saved = db.all()[0]
        db.close()
        loaded = Operation.from_dict(saved)
        self.__dict__.update(loaded.__dict__)


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

    def loadPentest(self) -> None:
        """Load the pentest from the TinyDB database"""
        f = open(f"{self.operation_name}.json")
        savedData = json.load(f)
        # First record, we shouldn't have more than one anyway, if so .. we shall revisit this
        print(savedData)
        self.__init__(**savedData["_default"]["1"])  # type: ignore[misc]
