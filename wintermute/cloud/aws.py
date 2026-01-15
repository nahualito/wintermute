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

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Type, TypeVar

from ..basemodels import BaseModel, CloudAccount
from ..findings import Vulnerability

log = logging.getLogger(__name__)

T = TypeVar("T", bound="BaseModel")


def _load_list(data: Optional[List[Any]], cls: Type[T]) -> List[T]:
    """
    Generic helper to parse a list of dictionaries or objects into a list of specific Objects.
    """
    if not data:
        return []

    results = []
    for item in data:
        if isinstance(item, cls):
            results.append(item)
        elif isinstance(item, dict):
            results.append(cls.from_dict(item))
        else:
            raise TypeError(f"Expected {cls.__name__} or dict, got {type(item)}")
    return results


# AWS Specific Classes
@dataclass
class AWSUser(BaseModel):
    username: str
    arn: str | None = None
    attached_policies: List[str] = field(default_factory=list)

    __schema__ = {}
    __enums__ = {}


@dataclass
class IAMUser(BaseModel):
    username: str
    arn: str | None = None
    administrator: bool = False
    attached_policies: List[str] = field(default_factory=list)

    __schema__ = {}
    __enums__ = {}


@dataclass
class IAMRole(BaseModel):
    role_name: str
    arn: str | None = None
    administrator: bool = False
    attached_policies: List[str] = field(default_factory=list)

    __schema__ = {}
    __enums__ = {}


class AWSServiceType(Enum):
    EC2 = "ec2"
    S3 = "s3"
    RDS = "rds"
    LAMBDA = "lambda"
    IAM = "iam"
    VPC = "vpc"
    CLOUDFRONT = "cloudfront"
    DYNAMODB = "dynamodb"
    SQS = "sqs"
    SNS = "sns"
    ELB = "elb"
    EKS = "eks"
    LEX = "lex"
    OTHER = "other"


@dataclass
class AWSService(BaseModel):
    name: str
    arn: str | None = None
    config: Dict[str, Any] = field(default_factory=dict)
    properties: Dict[str, Any] = field(default_factory=dict)
    service_type: AWSServiceType = AWSServiceType.OTHER

    __schema__ = {}
    __enums__ = {"service_type": AWSServiceType}


class AWSAccount(CloudAccount):
    """This class represents an AWS Account that may contain users and vulnerabilities.

    This class represents an AWS Account that may contain users and vulnerabilities,
    this class was not designed to be called by itself, it should be called from
    Operation for it's management

    Examples:
        >>> from wintermute.cloud.aws import AWSAccount, AWSUser, AWSService
        >>> from wintermute.findings import Vulnerability, Risk
        >>> acct = AWSAccount(
        ...     name="aws-prod",
        ...     description="This is the prod account",
        ...     account_id="123456789012",
        ...     arn="arn:aws:iam::123456789012:root",
        ...     default_region="us-east-1",
        ...     users=[
        ...         {"username": "alice"},
        ...         {"username": "bob", "attached_policies": ["Admin"]},
        ...     ],
        ...     services=[{"name": "s3", "resources": ["bucket1", "bucket2"]}],
        ...     vulnerabilities=[
        ...         Vulnerability(
        ...             title="Public S3",
        ...             description="Bucket allows public read",
        ...             risk=Risk(severity="High"),
        ...         ),
        ...     ],
        ... )
        >>> r.account_id
        '123456789012'
        >>> r.name
        'aws-prod'
        >>> r.description
        'This is the prod account'

    Attributes:
        * account_id (str): AWS Account ID
        * arn (str): AWS Account ARN
        * partition (str): AWS partition (aws, aws-us-gov, aws-cn)
        * default_region (str): Default AWS region for the account
        * tags (dict): Dictionary of tags associated with the account
        * users (list): List of AWSUser objects associated with the account
        * services (list): List of AWSService objects associated with the account
    """

    __schema__ = {
        "users": AWSUser,
        "services": AWSService,
        "iamusers": IAMUser,
        "iamroles": IAMRole,
    }

    def __init__(
        self,
        name: str,
        description: str = "",
        *,
        account_id: str | None = None,
        arn: str | None = None,
        partition: str = "aws",  # aws, aws-us-gov, aws-cn
        default_region: str | None = None,
        tags: Dict[str, str] | None = None,
        users: Optional[List[AWSUser | Dict[str, Any]]] = None,
        iamusers: Optional[List[IAMUser | Dict[str, Any]]] = None,
        iamroles: Optional[List[IAMRole | Dict[str, Any]]] = None,
        services: Optional[List[AWSService | Dict[str, Any]]] = None,
        vulnerabilities: Optional[List[Any]] = None,
        roles: Optional[List[Any]] = None,
    ) -> None:
        # let CloudAccount handle name/description/vulnerabilities coercion
        super().__init__(
            name=name, description=description, vulnerabilities=vulnerabilities
        )

        self.account_id = account_id
        self.arn = arn
        self.partition = partition
        self.default_region = default_region
        self.tags = dict(tags) if tags else {}
        self.roles = roles if roles else []

        self.users: List[AWSUser] = _load_list(users, AWSUser)
        self.iamusers: List[IAMUser] = _load_list(iamusers, IAMUser)
        self.iamroles: List[IAMRole] = _load_list(iamroles, IAMRole)
        self.services: List[AWSService] = _load_list(services, AWSService)

    # Optional: convenience
    @property
    def provider(self) -> str:
        return "aws"

    def _add_component(self, target_list: List[T], cls: Type[T], **kwargs: Any) -> bool:
        """
        Internal helper to construct an object, check for duplicates, and append.
        """
        # Create the object using the provided class and keyword arguments
        obj = cls(**kwargs)

        # Check if it already exists (requires __eq__ or dataclass default equality)
        if obj not in target_list:
            target_list.append(obj)
            return True
        return False

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
        self, username: str, arn: str | None = None, attached_policies: List[str] = []
    ) -> bool:
        # We assume attached_policies defaults to empty list in the dataclass if None passed
        return self._add_component(
            self.users,
            AWSUser,
            username=username,
            arn=arn,
            attached_policies=attached_policies or [],
        )

    def addIAMUser(
        self,
        username: str,
        arn: str | None = None,
        administrator: bool = False,
        attached_policies: List[str] = [],
    ) -> bool:
        return self._add_component(
            self.iamusers,
            IAMUser,
            username=username,
            arn=arn,
            administrator=administrator,
            attached_policies=attached_policies or [],
        )

    def addIAMRole(
        self,
        role_name: str,
        arn: str | None = None,
        administrator: bool = False,
        attached_policies: List[str] = [],
    ) -> bool:
        return self._add_component(
            self.iamroles,
            IAMRole,
            role_name=role_name,
            arn=arn,
            administrator=administrator,
            attached_policies=attached_policies or [],
        )

    def addService(
        self,
        name: str,
        service_type: AWSServiceType,
        config: Dict[str, Any] = {},
        properties: Dict[str, Any] = {},
    ) -> bool:
        return self._add_component(
            self.services,
            AWSService,
            name=name,
            service_type=service_type,
            config=config or {},
            properties=properties or {},
        )
