# tests/test_tickets.py
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from wintermute.tickets import (
    Comment,
    InMemoryBackend,  # if you placed it elsewhere, import accordingly
    Status,
    Ticket,
    TicketData,
)


def test_metaclass_injects_api_and_memory_backend_crud() -> None:
    mem = InMemoryBackend()
    Ticket.register_backend("mem", mem, make_default=True)

    tid = Ticket.create(
        title="Demo",
        description="Hello",
        requester="qa@x",
        assignee="dev@x",
        status=Status.OPEN,
        custom_fields={"cf_env": "staging"},
    )
    assert re.match(r"T\d{6}", tid)

    Ticket.comment(tid, text="first!", author="qa")

    tk = Ticket.read(tid)
    assert tk.ticket_id == tid
    assert tk.data.title == "Demo"
    assert tk.data.description == "Hello"
    assert tk.data.assignee == "dev@x"
    assert tk.data.requester == "qa@x"
    assert tk.data.status is Status.OPEN
    assert tk.comments and tk.comments[0].author == "qa"
    assert isinstance(tk.comments[0].at, datetime)

    Ticket.update(tid, status=Status.IN_PROGRESS, assignee="alice")
    tk2 = Ticket.read(tid)
    assert tk2.data.status is Status.IN_PROGRESS
    assert tk2.data.assignee == "alice"


def test_ticket_to_dict_and_from_dict_round_trip_handles_enum_and_datetime() -> None:
    c = Comment(
        author="qa", text="hi", at=datetime(2025, 10, 17, 13, 0, tzinfo=timezone.utc)
    )
    td = TicketData(
        title="Round trip",
        description="Serialize me",
        requester="me@x",
        assignee=None,
        status=Status.RESOLVED,
        communication=[c],
        custom_fields={"foo": "bar"},
    )
    t = Ticket(ticket_id="T000123", data=td, comments=[c])

    blob = t.to_dict()
    assert blob["data"]["status"] in {"resolved", "RESOLVED"}
    assert isinstance(blob["comments"][0]["at"], str)

    blob2 = json.loads(json.dumps(blob))
    t2 = Ticket.from_dict(blob2)

    assert t2.ticket_id == "T000123"
    assert t2.data.title == "Round trip"
    assert t2.data.custom_fields["foo"] == "bar"
    assert t2.data.status is Status.RESOLVED
    assert isinstance(t2.comments[0].at, datetime)


def test_switching_backends_changes_behavior_without_touching_callsites() -> None:
    mem_a = InMemoryBackend()
    mem_b = InMemoryBackend()

    Ticket.register_backend("A", mem_a, make_default=True)
    tid_a = Ticket.create(title="A", description="a")
    Ticket.comment(tid_a, "on A", "qa")
    got_a = Ticket.read(tid_a)
    assert got_a.data.title == "A"

    Ticket.register_backend("B", mem_b)
    Ticket.use_backend("B")
    tid_b = Ticket.create(title="B", description="b")
    Ticket.comment(tid_b, "on B", "qa")
    got_b = Ticket.read(tid_b)
    assert got_b.data.title == "B"

    Ticket.use_backend("A")
    again_a = Ticket.read(tid_a)
    assert again_a.data.title == "A"
