# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use, line-too-long

"""
Core classes for OnoSendai
---------------------------

This file contains the core classes for the onoSendai deck, these are not going to be exported
to the deck, they are for internal deck use.
"""

import ipaddress
import json
import re
import uuid
from datetime import datetime
from typing import Any, Dict, Sequence, Union

from tinydb import Query, TinyDB


class ReproductionStep:
    """This class holds a reproduction step for vulnerabilities"""

    def __init__(self) -> None:
        self.tool = None
        self.action = None
        self.confidence = 0
        self.arguments: Sequence[str] = []
        self.vulnOutput = None
        self.fixOutput = None
        pass

    def toJSON(self) -> str:
        return json.dumps(
            self,
            default=lambda o: o.__dict__ if "__dict__" in dir(o) else o.name,
            sort_keys=True,
            indent=4,
        )


class Vulnerability:
    """This class holds a vulnerability found"""

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
        risk: Dict[Any, Any] = {},
        verified: bool = False,
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
        self.reproduction_steps: Sequence[ReproductionStep] = []
        self.risk = Risk()
        if risk is not None:
            self.setRisk(**risk)

    def setRisk(
        self, likelihood: str = "Low", impact: str = "Low", severity: str = "Low"
    ) -> None:
        self.risk.likelihood = likelihood
        self.risk.impact = impact
        self.risk.severity = severity

    def toJSON(self) -> str:
        return json.dumps(
            self,
            default=lambda o: o.__dict__ if "__dict__" in dir(o) else o.name,
            sort_keys=True,
            indent=4,
        )


class Risk:
    """This class defines and holds the Risks, it inherits from the Vulns

    This class defines the risk for the vulnerability is assigned to, is designed to
    be used by a vulnerability itself

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

    def toJSON(self) -> str:
        return json.dumps(
            self,
            default=lambda o: o.__dict__ if "__dict__" in dir(o) else o.name,
            sort_keys=True,
            indent=4,
        )


class AWSAccount:
    """This class holds the model of the AWS accounts

    This class holds the AWS account details, including vulnerabilities found within them.

    Attributes:
        * accountId (str): Id number of the AWS account
        * name (str): Name of the AWS account
        * description (str): Description of the AWS account
        * vulnerabilities (array): Vulnerabilities assigned to the account
    """

    def __init__(
        self,
        accountId: str = "",
        name: str = "",
        description: str = "",
        vulnerabilities: list[Vulnerability] = [],
    ) -> None:
        self.accountId = accountId
        self.name = name
        self.description = description
        self.vulnerabilities: list[Vulnerability] = []
        if vulnerabilities is not None:
            vulnerability: Vulnerability
            for vulnerability in vulnerabilities:
                # self.addVulnerability(**vulnerability)
                self.addVulnerability(vulnerability.toJSON())
        pass

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
    ) -> None:
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

    def toJSON(self) -> str:
        return json.dumps(
            self,
            default=lambda o: o.__dict__ if "__dict__" in dir(o) else o.name,
            sort_keys=True,
            indent=4,
        )


class Service:
    """This class holds the network port objects

    This class holds the network port objects and will allow to track states, versions and vulns.

    Attributes:
        * protocol (str): Transport protocol (ipv4/ipv6)
        * app (str): Application running in the port
        * portNumber (int): port the service is listening on
        * banner (str): Banner of the service
        * transport_layer (str): Application protocol (HTTP, HTTPS, FTP, SSH, etc)
    """

    def __init__(
        self,
        protocol: str = "ipv4",
        app: str = "",
        portNumber: int = 0,
        banner: str = "",
        transport_layer: str = "",
        vulnerabilities: list[Vulnerability] = [],
    ) -> None:
        self.protocol = protocol
        self.app = app
        self.portNumber = portNumber
        self.banner = banner
        self.transport_layer = transport_layer  # HTTP, HTTPS, FTP, SSH, etc.
        # Array of vulnerability objects related with the port
        self.vulnerabilities: list[Vulnerability] = []
        if vulnerabilities is not None:
            for vulnerability in vulnerabilities:
                # self.addVulnerability(**vulnerability)
                self.addVulnerability(vulnerability.toJSON())
        pass

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
    ) -> None:
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

    def toJSON(self) -> str:
        return json.dumps(
            self,
            default=lambda o: o.__dict__ if "__dict__" in dir(o) else o.name,
            sort_keys=True,
            indent=4,
        )


class Device:
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

    def __init__(
        self,
        hostname: str = "",
        ipaddr: Union[
            ipaddress.IPv4Address, ipaddress.IPv6Address
        ] = ipaddress.ip_address("127.0.0.1"),
        macaddr: str = "",
        operatingsystem: str = "",
        fqdn: str = "",
        services: list[Service] = [],
    ) -> None:
        self.hostname = hostname
        self.ipaddr = ipaddress.ip_address(ipaddr) if ipaddr else None
        self.macaddr = macaddr
        self.operatingsystem = operatingsystem
        self.fqdn = fqdn
        self.services: list[Service] = []
        if services is not None:
            for service in services:
                # self.addService(**service)
                self.addService(service.toJSON())

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

    def toJSON(self) -> str:
        return json.dumps(
            self,
            default=lambda o: o.__dict__ if "__dict__" in dir(o) else str(o),
            sort_keys=True,
            indent=4,
        )


class User:
    """This class holds the user object.

    This class represents a user that is to be targetted by the operation, this can
    be a user for a team that is NOT the operational team, can be a stakeholder and other.
    """

    def __init__(
        self,
        uid: str = "",
        name: str = "",
        email: str = "",
        dept: str = "",
        permissions: Sequence[str] = [],
        override_reason: str = "",
        AWSAdminAccounts: Sequence[AWSAccount] = [],
        AWSLoginAccounts: Sequence[AWSAccount] = [],
        desktops: list[Device] = [],
        ldap_groups: Sequence[str] = [],
        teams: Sequence[str] = [],
    ) -> None:
        self.uid = uid
        self.name = name
        self.email = email
        self.dept = dept
        self.permissions = permissions
        self.override_reason = override_reason
        self.desktops: list[Device] = []
        self.ldap_groups: list[str] = []
        self.teams: list[str] = []
        self.AWSAdminAccounts: list[AWSAccount] = []
        self.AWSLoginAccounts: list[AWSAccount] = []

        if teams is not None:
            for team in teams:
                if team not in self.teams:
                    self.teams.append(team)

        if desktops is not None:
            self.desktops = desktops

        if AWSAdminAccounts is not None:
            for account in AWSAdminAccounts:
                # acct = AWSAccount(**account)
                acct = AWSAccount(account.toJSON())
                self.AWSAdminAccounts.append(acct)

        if email is None and self.uid is not None:
            self.email = f"{self.uid}@stubemail.com"

        pass

    def toJSON(self) -> str:
        return json.dumps(
            self,
            default=lambda o: o.__dict__ if "__dict__" in dir(o) else o.name,
            sort_keys=True,
            indent=4,
        )


class Analyst:
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

    def toJSON(self) -> str:
        return json.dumps(
            self,
            default=lambda o: o.__dict__ if "__dict__" in dir(o) else o.name,
            sort_keys=True,
            indent=4,
        )


class Operation:
    """This class contains the information about the operation including devices, analysts and name of the operation.

    This is the top level class to call on operations, while you can call all other classes such as EDR, Devices, etc.
    these classes will not have the automation capabilities added as incident, but they can be called for more
    flexibility on this library.

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

    def __init__(
        self,
        operation_name: str = "Wintermute",
        analysts: list[Analyst] = [],
        ticket: str = "",
        devices: list[Device] = [],
        end_date: str = datetime.today().strftime("%m/%d/%Y"),
        start_date: str = datetime.today().strftime("%m/%d/%Y"),
        users: list[User] = [],
        operation_id: str = str(uuid.uuid1()),
        awsaccounts: list[AWSAccount] = [],
        db: str = "",
    ) -> None:
        self.operation_name = operation_name
        self.db = TinyDB(f"{operation_name}.json")
        # Make a UUID based on the host ID and the current machine time.
        self.operation_id = operation_id
        self.analysts: list[Analyst] = []
        self.devices: list[Device] = []
        self.users: list[User] = []
        self.awsaccounts: list[AWSAccount] = []
        self.start_date: str = start_date
        self.end_date: str = end_date
        if analysts is not None:
            for analyst in analysts:
                # self.addAnalyst(**analyst)
                self.addAnalyst(analyst.toJSON())

        if devices is not None:
            for device in devices:
                # self.addDevice(**device)
                self.addDevice(device.toJSON())

        if users is not None:
            for user in users:
                # self.addUser(**user)
                self.addUser(*user.toJSON())

        if awsaccounts is not None:
            for aws_account in awsaccounts:
                # self.addAWSAccount(**aws_account)
                self.addAWSAccount(*aws_account.toJSON())

        self.ticket = ticket if ticket else None

    @property
    def dbOperation(self) -> TinyDB:
        return self.db

    @dbOperation.setter
    def dbOperation(self, value: str) -> None:
        if value is not None:
            self.operation_name = value
            self.db = TinyDB(f"{value}.json")

    def addAnalyst(self, name: str = "", userid: str = "", email: str = "") -> bool:
        # We check we actually have
        if all(v is not None for v in [name, userid, email]):
            # We create the object then add it to the array
            analyst = Analyst(name=name, userid=userid, email=email)
            if analyst not in self.analysts:
                self.analysts.append(analyst)
                return True
        return False

    def deleteAnalyst(self, name: str = "", userid: str = "", email: str = "") -> bool:
        if all(v is not None for v in [name, userid, email]):
            # We create the object then add it to the array
            analyst = Analyst(name=name, userid=userid, email=email)
            if analyst not in self.analysts:
                self.analysts.remove(analyst)
                return True
        return True

    def addDevice(
        self,
        hostname: str = "",
        ipaddr: Union[
            ipaddress.IPv4Address, ipaddress.IPv6Address
        ] = ipaddress.ip_address("127.0.0.1"),
        macaddr: str = "",
        operatingsystem: str = "",
        fqdn: str = "",
        services: list[Service] = [],
    ) -> bool:
        dev = Device(
            hostname=hostname,
            ipaddr=ipaddr,
            macaddr=macaddr,
            operatingsystem=operatingsystem,
            fqdn=fqdn,
            services=services,
        )
        if dev not in self.devices:
            self.devices.append(dev)
            return True
        return False

    def addUser(self, **kwargs) -> bool:  # type: ignore
        u = User(**kwargs)
        if u not in self.users:
            self.users.append(u)
            return True
        return False

    def addAWSAccount(self, **kwargs) -> bool:  # type: ignore
        a = AWSAccount(**kwargs)
        if a not in self.awsaccounts:
            self.awsaccounts.append(a)
            return True
        return False

    def load(self) -> None:
        f = open(f"{self.operation_name}.json")
        savedData = json.load(f)
        # First record, we shouldn't have more than one anyway, if so .. we shall revisit this
        self.__init__(**savedData["_default"]["1"])  # type: ignore[misc]

    def save(self) -> None:
        self.db.upsert(
            json.loads(self.toJSON()), Query().operation_name == self.operation_name
        )
        pass

    def toJSON(self) -> str:
        return json.dumps(
            self,
            default=lambda o: o.__dict__ if "__dict__" in dir(o) else o.name,
            indent=4,
        )


class Pentest(Operation):
    """Pentest class

    This class inherits from the Operation class (The main and original class) extending things such as the ANVIL appId,
    the application id, the classification for the data in the app, users that hold the pentest, stakeholders, etc.

    Attributes:
        * ApplicationName (str): Name of the application (default is 'DefaultApp')
        * ANVIL (str): ANVIL application id
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
            ANVIL (str): ANVIL application id
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
        f = open(f"{self.operation_name}.json")
        savedData = json.load(f)
        # First record, we shouldn't have more than one anyway, if so .. we shall revisit this
        print(savedData)
        self.__init__(**savedData["_default"]["1"])  # type: ignore[misc]

    def save(self) -> None:
        self.db.upsert(
            json.loads(self.toJSON()), Query().operation_name == self.operation_name
        )
        pass
