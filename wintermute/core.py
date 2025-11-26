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
from datetime import datetime
from typing import Any, Dict, Sequence

from tinydb import TinyDB

from .basemodels import BaseModel, CloudAccount, Peripheral
from .findings import Vulnerability

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
        * architecture (str): Architecture of the machine (x86, x64, ARM, etc)
        * chipset (str): Chipset of the machine (Maxis, ARM7, Cortex, etc)
        * services (array): Array of Service objects holding the open services on the machine.
        * peripherals (array): Array of Peripheral objects connected to the machine.
    """

    __schema__ = {
        "services": Service,
        "peripherals": Peripheral,
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
        architecture: str = "",
        chipset: str = "",
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
        self.chipset = chipset
        self.services: list[Service] = []
        self.peripherals: list[Peripheral] = []

        for s in services or []:
            self.services.append(Service.from_dict(s) if isinstance(s, dict) else s)

        for p in peripherals or []:
            self.peripherals.append(
                Peripheral.from_dict(p) if isinstance(p, dict) else p
            )

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


class AWSAccount(CloudAccount):
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
                    log.debug(
                        f"Rehydrated vulnerability {v.get('title', 'unknown')} for AWSAccount {self.accountId}"
                    )
                elif isinstance(v, Vulnerability):
                    self.vulnerabilities.append(v)
                    log.debug(
                        f"Added existing vulnerability {v.title} for AWSAccount {self.accountId}"
                    )

        # Rehydrate users
        self.users: list[User] = []
        if users:
            for u in users:
                if isinstance(u, dict):
                    self.users.append(User.from_dict(u))
                    log.debug(
                        f"Rehydrated user {u.get('uid', 'unknown')} for AWSAccount {self.accountId}"
                    )
                elif isinstance(u, User):
                    self.users.append(u)
                    log.debug(
                        f"Added existing user {u.uid} for AWSAccount {self.accountId}"
                    )

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
            return True
        return False

    def delAnalyst(self, userid: str) -> bool:
        """Delete an analyst from the operation by userid"""
        for a in self.analysts:
            if a.userid == userid:
                self.analysts.remove(a)
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

    def delDevice(self, hostname: str) -> bool:
        """Delete a device from the operation by hostname"""
        for d in self.devices:
            if d.hostname == hostname:
                self.devices.remove(d)
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

    def delUser(self, uid: str) -> bool:
        """Delete a user from the operation by uid"""
        for u in self.users:
            if u.uid == uid:
                self.users.remove(u)
                return True
        return False

    def addAWSAccount(self, accountId: str, name: str, description: str = "") -> bool:
        """Add an AWS Account to the operation"""
        a = AWSAccount(accountId, name, description)
        if a not in self.awsaccounts:
            self.awsaccounts.append(a)
            return True
        return False

    def delAWSAccount(self, accountId: str) -> bool:
        """Delete an AWS Account from the operation by accountId"""
        for a in self.awsaccounts:
            if a.accountId == accountId:
                self.awsaccounts.remove(a)
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
