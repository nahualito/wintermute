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

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

__category__ = "Ticketing"
__description__ = "Vulnerability & incident tracking via Bugzilla REST API."

if TYPE_CHECKING:
    # type-only to avoid circular imports at runtime
    from wintermute.tickets import Comment, TicketData


# --------- helpers: URL + auth ---------


def _extract_bug_id(js: Any) -> Optional[str]:
    """
    Try to extract a bug id from various Bugzilla create responses.
    Compatible with:
      - {"id": 123}
      - {"bug_id": 123}
      - {"bug": {"id": 123, ...}}
      - {"bugs": [{"id": 123, ...}, ...]}
      - {"bugs": {"123": {...}}}
    Returns None if nothing suitable is found.
    """
    if not isinstance(js, dict):
        return None

    # Simple cases
    if "id" in js:
        return str(js["id"])
    if "bug_id" in js:
        return str(js["bug_id"])

    # {"bug": {...}}
    bug = js.get("bug")
    if isinstance(bug, dict):
        if "id" in bug:
            return str(bug["id"])
        if "bug_id" in bug:
            return str(bug["bug_id"])

    # {"bugs": [...]}
    bugs = js.get("bugs")
    if isinstance(bugs, list) and bugs:
        first = bugs[0]
        if isinstance(first, dict):
            if "id" in first:
                return str(first["id"])
            if "bug_id" in first:
                return str(first["bug_id"])

    # {"bugs": {"123": {...}}}
    if isinstance(bugs, dict) and bugs:
        # take first key
        key = next(iter(bugs.keys()))
        return str(key)

    return None


def _unpack_ticket_like(obj: Any) -> Dict[str, Any]:
    """
    Accepts:
      - dict(...)        -> returned as-is
      - TicketData(...)  -> obj.to_dict()
      - Ticket(...)      -> obj.data.to_dict()
      - any object with attributes: title, description, assignee, requester, status, custom_fields
    Returns a dict with at least those keys if present.
    """
    if isinstance(obj, dict):
        data = dict(obj)
    else:
        # If it's a Ticket wrapper, drop to its 'data'
        candidate = getattr(obj, "data", obj)
        if hasattr(candidate, "to_dict"):
            data = candidate.to_dict()
        else:
            # Build from attrs
            keys = (
                "title",
                "description",
                "assignee",
                "requester",
                "status",
                "custom_fields",
            )
            data = {k: getattr(candidate, k) for k in keys if hasattr(candidate, k)}
    # ensure custom_fields is a dict if present/needed
    if not isinstance(data.get("custom_fields"), dict):
        # normalize None or missing to {}
        data["custom_fields"] = (
            {} if data.get("custom_fields") is None else data.get("custom_fields", {})
        )
    return data


def _status_name(value: Any) -> str:
    """Return a lower-case status name from string or Enum; empty string if unknown."""
    if isinstance(value, Enum):
        return value.name.lower()
    if isinstance(value, str):
        return value.lower()
    return ""


def _normalize_rest_base(base_url: str) -> str:
    b = base_url.rstrip("/") + "/"
    if b.endswith("/rest/"):
        return b
    # user may have given ".../bugzilla" or ".../bugzilla/"
    if b.endswith("/bugzilla/"):
        return b + "rest/"
    # already ".../rest" (no slash)
    if b.endswith("/rest/") is False and b.endswith("/rest"):
        return b + "/"
    # fallback: assume it's the root and append rest/
    return b + "rest/"


def _status_to_ticket(status: str) -> str:
    # Bugzilla common statuses → Ticket.Status names (lower-case strings)
    s = status.upper()
    if s in {"NEW", "UNCONFIRMED", "CONFIRMED"}:
        return "open"
    if s in {"IN_PROGRESS", "ASSIGNED"}:
        return "in_progress"
    if s in {"RESOLVED"}:
        return "resolved"
    if s in {"VERIFIED"}:
        return "resolved"  # or a custom "verified" if you have it
    if s in {"CLOSED"}:
        return "closed"
    return "open"


def _status_from_ticket(status_name: str) -> str:
    # Ticket.Status (enum name/lowercase) → Bugzilla status string
    s = status_name.lower()
    if s in {"open", "new"}:
        return "NEW"
    if s in {"in_progress", "assigned"}:
        return "ASSIGNED"
    if s in {"resolved", "done"}:
        return "RESOLVED"
    if s in {"closed"}:
        return "CLOSED"
    return "NEW"


@dataclass
class BugzillaBackend:
    """
    Minimal Bugzilla backend that satisfies the Ticket backend protocol.

    Example:
    >>> from wintermute.backends.bugzilla import BugzillaBackend
    >>> from wintermute.tickets import Ticket
    >>>
    >>> backend = BugzillaBackend(
    ...     base_url="http://192.168.0.145/bugzilla",  # or ".../bugzilla/rest"
    ...     api_key="YOUR_API_KEY_HERE",
    ...     default_product="MyProduct",
    ...     default_component="Backend",
    ... )
    >>>
    >>> Ticket.register_backend("bugzilla", backend, make_default=True)
    >>> tid = Ticket.create(
    ...     title="Sign-in fails on Safari",
    ...     description="Repro: ...",
    ...     assignee="nahualito@localhost.dev",
    ...     requester="root@localhost.dev",
    ...     # optional: override product/component at creation-time:
    ...     custom_fields={
    ...         "product": "TestProduct",
    ...         "component": "TestComponent",
    ...         "op_sys": "Windows",
    ...         "rep_platform": "All",
    ...         "version": "unspecified",
    ...     },
    ... )
    >>> t = Ticket.read(tid)
    >>> Ticket.comment(
    ...     tid, text="Added HAR and screen recording", author="nahualito@localhost.dev"
    ... )
    >>> Ticket.update(tid, status="resolved")

    Arguments:
        * base_url: e.g. "http://host/bugzilla/rest" or "http://host/bugzilla"
        * api_key:  Bugzilla API key with permissions on your product/component
    """

    base_url: str
    api_key: str
    default_product: Optional[str] = None
    default_component: Optional[str] = None

    # runtime
    _rest_base: str = ""
    _session: requests.Session = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self._rest_base = _normalize_rest_base(self.base_url)
        self._session = requests.Session()
        # Some Bugzilla installs accept header, some only the query param. Do both.
        self._session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-BUGZILLA-API-KEY": self.api_key,
            }
        )

    # ---------- HTTP helpers ----------

    def _u(self, path: str) -> str:
        return urljoin(self._rest_base, path)

    def _q(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        q: Dict[str, Any] = {"api_key": self.api_key}
        if extra:
            q.update(extra)
        return q

    def _check(self, r: requests.Response, action: str) -> None:
        try:
            r.raise_for_status()
        except requests.HTTPError:
            msg = ""
            try:
                js = r.json()
                msg = js.get("message") or js.get("error") or ""
            except Exception:
                pass
            req = r.request
            diag = f"{req.method} {req.url} [{r.status_code}] {msg}".strip()
            if r.status_code == 401:
                diag += " (auth failed: ensure api_key in query string; some servers ignore the header)"
            raise RuntimeError(f"Bugzilla {action} failed: {diag}") from None

    # ---------- Ticket facade methods ----------

    def create(self, data: Any) -> str:
        d = _unpack_ticket_like(data)

        # allow product/component to come from custom_fields (optional)
        cf = d.get("custom_fields") or {}
        product = d.get("product") or cf.get("product") or self.default_product
        component = d.get("component") or cf.get("component") or self.default_component
        if not product or not component:
            raise RuntimeError(
                "Bugzilla create needs product and component (set defaults or pass via custom_fields)"
            )

        payload: Dict[str, Any] = {
            "product": product,
            "component": component,
            "summary": d.get("title", "") or "",
            "description": d.get("description", "") or "",
        }

        assignee = d.get("assignee")
        if isinstance(assignee, str) and assignee:
            payload["assigned_to"] = assignee

        requester = d.get("requester")
        if isinstance(requester, str) and requester:
            payload["cc"] = [requester]

        # include arbitrary custom_fields (Bugzilla custom fields like cf_* get merged here)
        if isinstance(cf, dict):
            payload.update(cf)

        r = self._session.post(self._u("bug"), params=self._q(), json=payload)
        self._check(r, "create bug")
        js = r.json()
        bug_id = _extract_bug_id(js)
        if not bug_id:
            # include payload for debugging, but no secrets should be in the response body
            raise RuntimeError(
                f"Bugzilla create bug returned unexpected payload, no id found: {js!r}"
            )
        return bug_id

    def read(self, ticket_id: str) -> Tuple["TicketData", List["Comment"]]:
        """
        Read a bug from Bugzilla and return (TicketData, [Comment]) for Ticket.read().
        Description is taken from the first comment; all comments are converted.
        """
        from wintermute.tickets import Comment, Status, TicketData

        # 1) bug details
        r_bug = self._session.get(self._u(f"bug/{ticket_id}"), params=self._q())
        self._check(r_bug, "read bug")
        bug = r_bug.json()

        # Some Bugzilla APIs wrap the bug list
        if (
            isinstance(bug, dict)
            and "bugs" in bug
            and isinstance(bug["bugs"], list)
            and bug["bugs"]
        ):
            bug = bug["bugs"][0]

        # 2) comments
        r_com = self._session.get(self._u(f"bug/{ticket_id}/comment"), params=self._q())
        self._check(r_com, "read comments")
        cjs = r_com.json()

        comments: List[Comment] = []
        all_comments: List[dict[Any, Any]] = []

        # Newer format: {"bugs": {"<id>": {"comments": [ ... ]}}}
        bugs_block = cjs.get("bugs")
        if isinstance(bugs_block, dict):
            bug_entry = bugs_block.get(str(ticket_id))
            if isinstance(bug_entry, dict):
                maybe_comments = bug_entry.get("comments")
                if isinstance(maybe_comments, list):
                    all_comments = [c for c in maybe_comments if isinstance(c, dict)]

        # Fallback: {"comments": [ ... ]}
        if not all_comments:
            maybe = cjs.get("comments")
            if isinstance(maybe, list):
                all_comments = [c for c in maybe if isinstance(c, dict)]

        desc_text = ""
        for idx, c in enumerate(all_comments):
            text = str(c.get("text", "") or "")
            author = str(c.get("author", "") or "")
            if idx == 0:
                # First comment typically contains the long description
                desc_text = text
            comments.append(Comment(author=author, text=text))

        # 3) map status and fields into TicketData
        raw_status = str(bug.get("status", "NEW"))
        status_name = _status_to_ticket(raw_status)  # -> "open", "resolved", etc.
        status_enum = getattr(Status, status_name.upper(), Status.OPEN)

        td = TicketData(
            title=str(bug.get("summary", "") or ""),
            description=desc_text,
            assignee=(bug.get("assigned_to") or None),
            requester=(bug.get("creator") or None),
            status=status_enum,
            custom_fields={},  # optionally map bug fields here if you want
            communication=[],  # your Ticket holds comments separately
        )

        return td, comments

    def update(self, ticket_id: str, fields: Dict[str, Any]) -> None:
        """
        Adapter for Ticket.update().

        Ticket.update(...) calls backend.update(ticket_id, dict(fields)),
        so here `fields` is a plain dict like {"status": "resolved"} or
        {"title": "New title", "assignee": "...", "custom_fields": {...}, ...}.
        """
        d = fields
        payload: Dict[str, Any] = {}

        # Title → Bugzilla summary
        if "title" in d:
            payload["summary"] = d["title"]

        # Assignee → assigned_to
        if "assignee" in d and isinstance(d["assignee"], str):
            payload["assigned_to"] = d["assignee"]

        # Status mapping (Ticket status -> Bugzilla status)
        sname = _status_name(d.get("status"))
        if sname:
            bz_status = _status_from_ticket(sname)
            payload["status"] = bz_status

        # Description: Bugzilla generally doesn't let you overwrite the original
        # description directly; we add it as a new comment instead.
        if "description" in d and isinstance(d["description"], str):
            self.comment(ticket_id, text=d["description"])

        # Custom fields passthrough (e.g. cf_* fields, resolution, etc.)
        cf = d.get("custom_fields")
        if isinstance(cf, dict):
            payload.update(cf)

        # If we're moving to RESOLVED and no resolution is set, pick a default.
        # Your instance requires a resolution; "FIXED" is the safest generic default.
        if payload.get("status") == "RESOLVED" and "resolution" not in payload:
            payload["resolution"] = "FIXED"

        if payload:
            r = self._session.put(
                self._u(f"bug/{ticket_id}"),
                params=self._q(),
                json=payload,
            )
            self._check(r, "update bug")

    def add_comment(self, ticket_id: str, comment: Any) -> None:
        """
        Adapter method for Ticket.comment().

        Ticket.comment(...) creates a Comment object and calls:
            backend.add_comment(ticket_id, comment)

        So here we accept that Comment instance (or any object with .text/.author)
        and forward the actual text to the Bugzilla API.
        """
        # Local import to avoid circular dependency at module import time
        try:
            from wintermute.tickets import Comment
        except Exception:
            Comment = object  # type: ignore[misc,assignment]

        text: str
        author: Optional[str] = None

        if isinstance(comment, Comment):
            # Normal path: real Comment instance
            text = str(getattr(comment, "text", ""))
            a = getattr(comment, "author", None)
            author = str(a) if isinstance(a, str) else None
        else:
            # Fallback: treat it as a string-like payload
            text = str(comment)

        self.comment(ticket_id, text=text, author=author)

    def comment(self, ticket_id: str, text: str, author: Optional[str] = None) -> None:
        """
        Low-level Bugzilla comment call.
        `author` is usually ignored by Bugzilla; it infers from api_key user.
        """
        r = self._session.post(
            self._u(f"bug/{ticket_id}/comment"),
            params=self._q(),
            json={"comment": text},
        )
        self._check(r, "comment")
