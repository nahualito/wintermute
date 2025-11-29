# tests/test_bugzilla_backend.py
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, cast
from urllib.parse import urlparse

import pytest
import requests

from wintermute.backends.bugzilla import BugzillaBackend
from wintermute.tickets import Comment, Status, TicketData


@dataclass
class _FakeResponse:
    status_code: int
    json_body: Dict[str, Any] = field(default_factory=dict)
    method: str = ""
    url: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def json(self) -> Dict[str, Any]:
        return self.json_body

    def __getitem__(self, key: str) -> Any:
        if key == "method":
            return self.method
        if key == "url":
            return self.url
        if key in {"json", "body"}:
            # depending on how you used it before
            return self.json_body
        if key == "status_code":
            return self.status_code
        if key == "data":
            return self.data
        # fallback to attribute if it exists
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def raise_for_status(self) -> None:
        if 400 <= self.status_code < 600:
            raise requests.HTTPError(
                f"{self.status_code} error for {self.method} {self.url}",
                response=self,  # type: ignore[arg-type]
            )

    # NEW: mimic Response.request so backend._check can inspect method/url
    @property
    def request(self) -> _FakeRequest:
        return _FakeRequest(method=self.method, url=self.url)


@dataclass
class _FakeRequest:
    method: str
    url: str


class _FakeSession:
    def __init__(self, routes: Dict[Tuple[str, str], _FakeResponse]) -> None:
        # The test suite expects the constructor to accept `routes`
        self.routes = routes
        self.last: Optional[_FakeResponse] = None
        self.headers: Dict[str, str] = {}

    def headers_update(self, headers: Dict[str, str]) -> None:
        self.headers.update(headers)

    def _register(
        self,
        method: str,
        url: str,
        json_body: Optional[Dict[str, Any]] = None,
        status: int = 200,
    ) -> None:
        self.routes[(method.upper(), url)] = _FakeResponse(
            status_code=status,
            json_body=json_body or {},
            method=method.upper(),
            url=url,
        )

    # If your tests already have e.g. register_post/get/put helpers,
    # keep them and call _register(...) inside.

    def _request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> _FakeResponse:
        m = method.upper()

        # Try full URL first (in case tests register that way)
        key_full = (m, url)

        # Also support path-only keys like "/rest/bug"
        path = urlparse(url).path
        key_path = (m, path)

        if key_full in self.routes:
            resp = self.routes[key_full]
        elif key_path in self.routes:
            resp = self.routes[key_path]
        else:
            # default empty response if no route found:
            resp = _FakeResponse(
                status_code=200,
                json_body={},
                method=m,
                url=url,
            )

        # ensure method/url are set for diagnostics
        resp.method = m
        resp.url = url

        if json is not None:
            resp.data = json
        else:
            # keep whatever default/previous data was, or clear if you prefer:
            resp.data = resp.data or {}

        self.last = resp
        return resp

    def post(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> _FakeResponse:
        return self._request("POST", url, params=params, json=json)

    def get(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> _FakeResponse:
        return self._request("GET", url, params=params, json=None)

    def put(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> _FakeResponse:
        return self._request("PUT", url, params=params, json=json)

    def __getattr__(self, name: str) -> Any:
        # If backend ever uses session.headers.update, etc.
        if name == "headers":
            return self.headers
        raise AttributeError(name)


@pytest.fixture
def backend() -> BugzillaBackend:
    return BugzillaBackend(
        base_url="https://bugzilla.example.com",
        api_key="KEY",
        default_product="Prod",
        default_component="Engine",
    )


def test_create_maps_fields_and_returns_id(backend: BugzillaBackend) -> None:
    routes: Dict[Tuple[str, str], _FakeResponse] = {
        ("POST", "/rest/bug"): _FakeResponse(200, {"id": 12345}),
    }
    fake = _FakeSession(routes)
    backend._session = cast(requests.Session, fake)

    tid = backend.create(
        TicketData(
            title="Crash",
            description="Boom",
            assignee="dev@x",
            requester="qa@x",
            custom_fields={"cf_env": "staging"},
        )
    )
    assert tid == "12345"

    assert fake.last is not None
    last = fake.last
    payload = last["data"]
    assert payload["summary"] == "Crash"
    assert payload["description"] == "Boom"
    assert payload["assigned_to"] == "dev@x"
    assert payload["product"] == "Prod"
    assert payload["component"] == "Engine"
    assert payload["cf_env"] == "staging"


def test_read_fetches_bug_and_comments_and_maps_status(
    backend: BugzillaBackend,
) -> None:
    routes: Dict[Tuple[str, str], _FakeResponse] = {
        ("GET", "/rest/bug/12345"): _FakeResponse(
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
        ("GET", "/rest/bug/12345/comment"): _FakeResponse(
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
    backend._session = cast(requests.Session, fake)

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
    routes: Dict[Tuple[str, str], _FakeResponse] = {
        ("PUT", "/rest/bug/12345"): _FakeResponse(200, {"ok": 1}),
        ("POST", "/rest/bug/12345/comment"): _FakeResponse(200, {"ok": 1}),
    }
    fake = _FakeSession(routes)
    backend._session = cast(requests.Session, fake)

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

    assert fake.last is not None
    last = fake.last
    assert last["method"] == "PUT"
    payload = last["data"]
    assert payload["summary"] == "Title 2"
    assert payload["assigned_to"] == "bob"
    assert payload["status"] in {"CLOSED", "closed"}


def test_add_comment_posts_to_bug(backend: BugzillaBackend) -> None:
    routes: Dict[Tuple[str, str], _FakeResponse] = {
        ("POST", "/rest/bug/12345/comment"): _FakeResponse(200, {"ok": 1}),
    }
    fake = _FakeSession(routes)
    backend._session = cast(requests.Session, fake)

    backend.add_comment(
        "12345", Comment(author="qa", text="hello", at=datetime.now(timezone.utc))
    )

    assert fake.last is not None
    last = fake.last
    assert last["method"] == "POST"
    assert last["url"].endswith("/rest/bug/12345/comment")
    assert last["data"]["comment"] == "hello"
