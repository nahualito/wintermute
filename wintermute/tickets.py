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
from enum import Enum
from typing import (
    Any,
    ClassVar,
    Dict,
    List,
    MutableMapping,
    Optional,
    Protocol,
    Tuple,
    TypeVar,
    cast,
)

from .basemodels import BaseModel


# --- Protocol for backends (unchanged) ---
class TicketBackend(Protocol):
    def create(self, data: "TicketData") -> str: ...
    def read(self, ticket_id: str) -> Tuple["TicketData", List["Comment"]]: ...
    def update(self, ticket_id: str, fields: Dict[str, Any]) -> None: ...
    def add_comment(self, ticket_id: str, comment: "Comment") -> None: ...


T_Ticket = TypeVar("T_Ticket", bound="Ticket")


class Status(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


# --- Your BaseModel-based domain classes (abridged) ---
@dataclass
class Comment(BaseModel):
    author: str
    text: str
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    __schema__ = {}
    __enums__ = {}


@dataclass
class TicketData(BaseModel):
    title: str
    description: str
    assignee: Optional[str] = None
    requester: Optional[str] = None
    status: Status = Status.OPEN
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    communication: List[Comment] = field(default_factory=list)
    __schema__ = {"communication": Comment}
    __enums__ = {"status": Status}


# --- Metaclass with full typing and no ignores ---
class TicketMeta(type):
    def __new__(mcls, name: str, bases: Tuple[type, ...], ns: Dict[str, Any]) -> type:
        cls = super().__new__(mcls, name, bases, ns)
        c = cast(type["Ticket"], cls)  # for the type checker

        if not hasattr(c, "_backend"):
            c._backend = None
        if not hasattr(c, "_backends"):
            c._backends = {}

        def _require_backend(c_: type["Ticket"], /) -> TicketBackend:
            backend = c_._backend
            if backend is None:
                raise RuntimeError(f"No backend configured for {c_.__name__}")
            return backend

        def set_backend(c_: type["Ticket"], /, backend: TicketBackend) -> None:
            c_._backend = backend

        def register_backend(
            c_: type["Ticket"],
            /,
            name: str,
            backend: TicketBackend,
            *,
            make_default: bool = False,
        ) -> None:
            c_._backends[name] = backend
            if make_default or c_._backend is None:
                c_._backend = backend

        def use_backend(c_: type["Ticket"], /, name: str) -> None:
            c_._backend = c_._backends[name]

        def create(
            c_: type["Ticket"],
            /,
            *,
            title: str,
            description: str,
            assignee: Optional[str] = None,
            requester: Optional[str] = None,
            status: Status = Status.OPEN,
            custom_fields: Optional[Dict[str, Any]] = None,
        ) -> str:
            data = TicketData(
                title=title,
                description=description,
                assignee=assignee,
                requester=requester,
                status=status,
                custom_fields=custom_fields or {},
            )
            return _require_backend(c_).create(data)

        def read(c_: type["Ticket"], /, ticket_id: str) -> "Ticket":
            data, comments = _require_backend(c_).read(ticket_id)
            return c_(ticket_id=ticket_id, data=data, comments=list(comments))

        def update(c_: type["Ticket"], /, ticket_id: str, **fields: Any) -> None:
            _require_backend(c_).update(ticket_id, dict(fields))

        def comment(
            c_: type["Ticket"], /, ticket_id: str, text: str, author: str
        ) -> None:
            _require_backend(c_).add_comment(
                ticket_id, Comment(author=author, text=text)
            )

        c.set_backend = classmethod(set_backend)  # type: ignore[assignment]
        c.register_backend = classmethod(register_backend)  # type: ignore[assignment]
        c.use_backend = classmethod(use_backend)  # type: ignore[assignment]
        c.create = classmethod(create)  # type: ignore[assignment]
        c.read = classmethod(read)  # type: ignore[assignment]
        c.update = classmethod(update)  # type: ignore[assignment]
        c.comment = classmethod(comment)  # type: ignore[assignment]
        return cls


# --- Ticket class: declare ClassVars + stub classmethods (mypy sees them) ---
@dataclass
class Ticket(BaseModel, metaclass=TicketMeta):
    """Ticket model with backend-agnostic CRUD operations.

    This class provides a unified interface for creating, reading, updating,
    and commenting on tickets, regardless of the underlying backend system.

    Example:
        >>> # Configure once at startup:
        >>> Ticket.register_backend("mem", InMemoryBackend(), make_default=True)
        >>> Ticket.register_backend(
        ...     "bugzilla",
        ...     BugzillaBackend(base_url="https://bz.example", api_key="..."),
        ... )
        >>> Ticket.register_backend(
        ...     "sf", SalesforceBackend(instance_url="...", access_token="...")
        ... )
        >>> # App code stays vendor-agnostic:
        >>> tid = Ticket.create(title="Login bug", description="Fails on Safari")
        >>> Ticket.comment(tid, text="Reproduced on 17.0.3", author="qa-bot")
        >>> t = Ticket.read(tid)
        >>> t.change_status(Status.IN_PROGRESS)
        >>> # Switch the whole app to Salesforce later without touching call sites:
        >>> Ticket.use_backend("sf")


    Attributes:
        * ticket_id (str): Unique identifier of the ticket.
        * data (TicketData): Core data of the ticket.
        * comments (List[Comment]): List of comments associated with the ticket."""

    ticket_id: str
    data: TicketData
    comments: List[Comment] = field(default_factory=list)

    _backend: ClassVar[Optional[TicketBackend]] = None
    _backends: ClassVar[Dict[str, TicketBackend]] = {}

    @classmethod
    def set_backend(cls, backend: TicketBackend) -> None:
        raise NotImplementedError

    @classmethod
    def register_backend(
        cls, name: str, backend: TicketBackend, *, make_default: bool = False
    ) -> None:
        raise NotImplementedError

    @classmethod
    def use_backend(cls, name: str) -> None:
        raise NotImplementedError

    # NOTE: concrete types (no Type[T_Ticket]/T_Ticket)
    @classmethod
    def create(
        cls,
        *,
        title: str,
        description: str,
        assignee: Optional[str] = None,
        requester: Optional[str] = None,
        status: Status = Status.OPEN,
        custom_fields: Optional[Dict[str, Any]] = None,
    ) -> str:
        raise NotImplementedError

    @classmethod
    def read(cls, ticket_id: str) -> "Ticket":
        raise NotImplementedError

    @classmethod
    def update(cls, ticket_id: str, **fields: Any) -> None:
        raise NotImplementedError

    @classmethod
    def comment(cls, ticket_id: str, text: str, author: str) -> None:
        raise NotImplementedError

    __schema__ = {"data": TicketData, "comments": Comment}
    __enums__ = {}

    def to_dict(self) -> Dict[str, Any]:
        d = super().to_dict()
        d["data"]["status"] = self.data.status.value
        return d


# ---------- In Memory adapter for testing ----------
class InMemoryBackend:
    """In-memory ticket backend for testing and prototyping.

    Methods implement the TicketBackend protocol.

    Example:
        >>> # Configure once at startup:
        >>> Ticket.register_backend("mem", InMemoryBackend(), make_default=True)
        >>> # Your app code stays vendor-agnostic:
        >>> tid = Ticket.create(title="Login bug", description="Fails on Safari")
        >>> Ticket.comment(tid, text="Reproduced on 17.0.3", author="qa-bot")
        >>> t = Ticket.read(tid)
        >>> t.change_status(Status.IN_PROGRESS)
        >>> # Switch the whole app to Salesforce later without touching call sites:
        >>> Ticket.use_backend("sf")

    Attributes:
        * _db (Dict[str, TicketData]): In-memory storage of tickets.
        * _comments (Dict[str, List[Comment]]): In-memory storage of ticket comments.
        * _seq (int): Sequence counter for generating ticket IDs.
    """

    def __init__(self) -> None:
        self._db: Dict[str, TicketData] = {}
        self._comments: Dict[str, List[Comment]] = {}
        self._seq = 0

    def _next_id(self) -> str:
        self._seq += 1
        return f"T{self._seq:06d}"

    def create(self, data: TicketData) -> str:
        tid = self._next_id()
        self._db[tid] = data
        self._comments[tid] = list(data.communication)
        return tid

    def read(self, ticket_id: str) -> Tuple[TicketData, List[Comment]]:
        return (self._db[ticket_id], list(self._comments.get(ticket_id, [])))

    def update(self, ticket_id: str, fields: MutableMapping[str, Any]) -> None:
        d = self._db[ticket_id]
        for k, v in fields.items():
            if k == "status" and isinstance(v, str):
                v = Status(v)
            setattr(d, k, v)

    def add_comment(self, ticket_id: str, comment: Comment) -> None:
        self._comments.setdefault(ticket_id, []).append(comment)
