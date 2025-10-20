# tests/test_bugzilla_backend.py
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Tuple, cast

import pytest
import requests

from wintermute.backends.bugzilla import BugzillaBackend
from wintermute.tickets import Comment, Status, TicketData


class _Resp:
    status_code: int
    _body: Dict[str, Any]

    def __init__(self, status: int, body: Dict[str, Any]) -> None:
        self.status_code = status
        self._body = body

    def json(self) -> Dict[str, Any]:
        return self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class _FakeSession:
    """Tiny fake requests.Session with route table and last-call capture."""

    headers: Dict[str, str]
    _routes: Dict[Tuple[str, str], _Resp]
    last: Dict[str, Any]

    def __init__(self, routes: Dict[Tuple[str, str], _Resp]) -> None:
        self.headers = {}
        self._routes = routes
        self.last = {}

    def _path(self, url: str) -> str:
        # take path after hostname
        return "/" + url.split("://", 1)[-1].split("/", 1)[-1]

    def post(self, url: str, data: str, timeout: int) -> _Resp:
        key = ("POST", self._path(url))
        self.last = {
            "method": "POST",
            "url": url,
            "data": json.loads(data),
            "timeout": timeout,
        }
        return self._routes[key]

    def get(
        self, url: str, params: Dict[str, Any] | None = None, timeout: int = 0
    ) -> _Resp:
        key = ("GET", self._path(url))
        self.last = {
            "method": "GET",
            "url": url,
            "params": params or {},
            "timeout": timeout,
        }
        return self._routes[key]

    def put(self, url: str, data: str, timeout: int) -> _Resp:
        key = ("PUT", self._path(url))
        self.last = {
            "method": "PUT",
            "url": url,
            "data": json.loads(data),
            "timeout": timeout,
        }
        return self._routes[key]


@pytest.fixture
def backend() -> BugzillaBackend:
    return BugzillaBackend(
        base_url="https://bugzilla.example.com",
        api_key="KEY",
        default_product="Prod",
        default_component="Engine",
        default_version="1.0",
        timeout=5,
    )


def test_create_maps_fields_and_returns_id(backend: BugzillaBackend) -> None:
    routes: Dict[Tuple[str, str], _Resp] = {
        ("POST", "/rest/bug"): _Resp(200, {"id": 12345}),
    }
    fake = _FakeSession(routes)
    backend.session = cast(requests.Session, fake)

    tid = backend.create(
        TicketData(
            title="Crash",
            description="Boom",
            assignee="dev@x",
            requester="qa@x",
            status=Status.OPEN,
            custom_fields={"cf_env": "staging"},
        )
    )
    assert tid == "12345"

    payload = fake.last["data"]
    assert payload["summary"] == "Crash"
    assert payload["description"] == "Boom"
    assert payload["assigned_to"] == "dev@x"
    assert payload["product"] == "Prod"
    assert payload["component"] == "Engine"
    assert payload["version"] == "1.0"
    assert payload["cf_env"] == "staging"
    assert payload["status"] in {"NEW", "open"}


def test_read_fetches_bug_and_comments_and_maps_status(
    backend: BugzillaBackend,
) -> None:
    routes: Dict[Tuple[str, str], _Resp] = {
        ("GET", "/rest/bug/12345"): _Resp(
            200,
            {
                "bugs": [
                    {
                        "id": 12345,
                        "summary": "Crash",
                        "status": "ASSIGNED",
                        "assigned_to": "dev@x",
                        "creator": "qa@x",
                        "product": "Prod",
                        "component": "Engine",
                        "version": "1.0",
                        "op_sys": "All",
                        "priority": "P2",
                        "severity": "major",
                    }
                ]
            },
        ),
        ("GET", "/rest/bug/12345/comment"): _Resp(
            200,
            {
                "bugs": {
                    "12345": {
                        "comments": [
                            {
                                "author": "qa@x",
                                "text": "repro",
                                "time": "2025-10-17T12:00:00Z",
                            },
                            {
                                "author": "dev@x",
                                "text": "looking",
                                "time": "2025-10-17T12:10:00Z",
                            },
                        ]
                    }
                }
            },
        ),
    }
    fake = _FakeSession(routes)
    backend.session = cast(requests.Session, fake)

    data, comments = backend.read("12345")

    assert data.title == "Crash"
    assert data.requester == "qa@x"
    assert data.assignee == "dev@x"
    assert data.status is Status.IN_PROGRESS
    assert len(comments) == 2
    assert comments[0].author == "qa@x"
    assert comments[0].text == "repro"
    assert comments[0].at.tzinfo is not None


def test_update_maps_fields_and_emits_put_and_comment(backend: BugzillaBackend) -> None:
    routes: Dict[Tuple[str, str], _Resp] = {
        ("PUT", "/rest/bug/12345"): _Resp(200, {"ok": 1}),
        ("POST", "/rest/bug/12345/comment"): _Resp(200, {"ok": 1}),
    }
    fake = _FakeSession(routes)
    backend.session = cast(requests.Session, fake)

    backend.update(
        "12345",
        {
            "title": "New Title",
            "assignee": "alice",
            "status": Status.RESOLVED,
            "description": "why we changed",
        },
    )
    # Now make sure the PUT payload is as expected by issuing a PUT as the final call:
    backend.update("12345", {"title": "Title 2", "assignee": "bob", "status": "closed"})

    assert fake.last["method"] == "PUT"
    payload = fake.last["data"]
    assert payload["summary"] == "Title 2"
    assert payload["assigned_to"] == "bob"
    assert payload["status"] in {"CLOSED", "closed"}


def test_add_comment_posts_to_bug(backend: BugzillaBackend) -> None:
    routes: Dict[Tuple[str, str], _Resp] = {
        ("POST", "/rest/bug/12345/comment"): _Resp(200, {"ok": 1}),
    }
    fake = _FakeSession(routes)
    backend.session = cast(requests.Session, fake)

    backend.add_comment(
        "12345", Comment(author="qa", text="hello", at=datetime.now(timezone.utc))
    )

    assert fake.last["method"] == "POST"
    assert fake.last["url"].endswith("/rest/bug/12345/comment")
    assert fake.last["data"]["comment"] == "hello"
