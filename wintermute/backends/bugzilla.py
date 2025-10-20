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

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, MutableMapping, Optional, Tuple

import requests  # pip install types-requests for stubs

from ..tickets import Comment, Status, TicketData


def _parse_bugzilla_time(s: Optional[str]) -> datetime:
    """Parse Bugzilla time string into a datetime object.
    Bugzilla times are in ISO 8601 format, e.g., "2024-06-10T14:23:45Z".
    If the string is None or empty, returns the current UTC time.
    """
    if not s:
        return datetime.now(timezone.utc)
    s2 = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        return datetime.fromisoformat(s2)
    except Exception:
        # last resort: strip fractional seconds if present
        core = s2.split(".")[0]
        return datetime.fromisoformat(core)


@dataclass
class BugzillaBackend:
    """Bugzilla backend for Wintermute ticketing system.
    Uses the Bugzilla REST API.

    Example usage:
        >>> backend = BugzillaBackend(
                base_url="https://bugzilla.example.com",
                api_key="your_api_key_here",
                default_product="MyProduct",
                default_component="MyComponent",
            )
        >>> Ticket.register_backend("bugzilla", bz, make_default=True)
        >>> tid = Ticket.create(
                title="Sign-in fails on Safari",
                description="Repro: ...",
                assignee="alice@example.com",
                requester="qa@example.com",
            )
        >>> ticket = Ticket.read(tid)
        >>> print(ticket)
        >>> ticket.update(status=Status.IN_PROGRESS)


    Attributes:
        base_url: Base URL of the Bugzilla instance (e.g., "https://bugzilla.example.com"). No trailing slash.
        api_key: API key for authentication.
        default_product: Default product name for ticket creation.
        default_component: Default component name for ticket creation.
        default_version: Default version name for ticket creation. Defaults to "unspecified".
        timeout: Timeout for HTTP requests in seconds. Defaults to 30.
        status_out_map: Mapping from Wintermute Status values to Bugzilla status strings.
        status_in_map: Mapping from Bugzilla status strings to Wintermute Status values.
    """

    base_url: str
    api_key: str
    default_product: str
    default_component: str
    default_version: str = "unspecified"
    timeout: int = 30

    # Never assign None to dict-typed attributes; use default_factory
    status_out_map: Dict[str, str] = field(default_factory=dict)
    status_in_map: Dict[str, str] = field(default_factory=dict)

    # Make session definitely-present after __post_init__
    session: requests.Session = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Initialize the HTTP session and set up headers.
        Also fills in default status mappings if not provided.
        """
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-BUGZILLA-API-KEY": self.api_key,
            }
        )
        # Fill defaults only if caller didn’t provide a custom mapping
        if not self.status_out_map:
            self.status_out_map = {
                "open": "NEW",
                "in_progress": "ASSIGNED",
                "resolved": "RESOLVED",
                "closed": "CLOSED",
            }
        if not self.status_in_map:
            self.status_in_map = {
                "NEW": "open",
                "UNCONFIRMED": "open",
                "ASSIGNED": "in_progress",
                "IN_PROGRESS": "in_progress",  # if your instance uses it
                "RESOLVED": "resolved",
                "CLOSED": "closed",
                "VERIFIED": "resolved",
            }

    # ---------- TicketBackend implementation ----------

    def create(self, data: TicketData) -> str:
        """Create a new Bugzilla bug from TicketData.
        Returns the created bug ID as a string.
        """
        url = f"{self.base_url}/rest/bug"
        payload = self._compose_create_payload(data)
        r = self.session.post(url, data=json.dumps(payload), timeout=self.timeout)
        self._check(r, "create bug")
        body = r.json()
        bug_id = body.get("id")
        if bug_id is None:
            raise RuntimeError(f"Bugzilla create: missing id in response: {body}")
        return str(bug_id)

    def read(self, ticket_id: str) -> Tuple[TicketData, List[Comment]]:
        """Read a Bugzilla bug and its comments by ticket ID.
        Returns a tuple of TicketData and a list of Comments.
        """
        # bug record
        r_bug = self.session.get(
            f"{self.base_url}/rest/bug/{ticket_id}",
            params={
                "include_fields": "id,summary,status,assigned_to,creator,product,component,version,op_sys,priority,severity"
            },
            timeout=self.timeout,
        )
        self._check(r_bug, "read bug")
        bugs = r_bug.json().get("bugs", [])
        if not bugs:
            raise RuntimeError(f"Bugzilla read: bug {ticket_id} not found")
        b = bugs[0]

        # comments
        r_c = self.session.get(
            f"{self.base_url}/rest/bug/{ticket_id}/comment", timeout=self.timeout
        )
        self._check(r_c, "read comments")
        j = r_c.json()
        bug_key = str(ticket_id)
        bucket = j.get("bugs", {}).get(bug_key) or j.get("bugs", {}).get(
            int(ticket_id), {}
        )
        raw_comments = bucket.get("comments", [])

        comments: List[Comment] = [
            Comment(
                author=str(c.get("author", "")),
                text=str(c.get("text", "")),
                at=_parse_bugzilla_time(c.get("time")),
            )
            for c in raw_comments
        ]

        td = self._compose_ticket_data_from_bug(b, comments)
        return td, comments

    def update(self, ticket_id: str, fields: MutableMapping[str, Any]) -> None:
        """Update a Bugzilla bug with the given fields.
        Supported fields: title, assignee, status, description (as a comment).
        Custom fields prefixed with "cf_" are passed through.
        """
        comment_text: Optional[str] = None

        payload: Dict[str, Any] = {}
        if "title" in fields:
            payload["summary"] = fields.pop("title")
        if "assignee" in fields:
            payload["assigned_to"] = fields.pop("assignee")
        if "status" in fields:
            sv = fields.pop("status")
            if isinstance(sv, Status):
                sv = sv.value
            payload["status"] = self.status_out_map.get(str(sv), str(sv))

        # pass-through Bugzilla custom fields
        for k in list(fields.keys()):
            if str(k).startswith("cf_"):
                payload[k] = fields.pop(k)

        # emulate description update via a comment
        if "description" in fields:
            comment_text = str(fields.pop("description"))

        if payload:
            r = self.session.put(
                f"{self.base_url}/rest/bug/{ticket_id}",
                data=json.dumps(payload),
                timeout=self.timeout,
            )
            self._check(r, "update bug")

        if comment_text:
            self.add_comment(ticket_id, Comment(author="", text=comment_text))

    def add_comment(self, ticket_id: str, comment: Comment) -> None:
        """Add a comment to a Bugzilla bug."""
        r = self.session.post(
            f"{self.base_url}/rest/bug/{ticket_id}/comment",
            data=json.dumps({"comment": comment.text}),
            timeout=self.timeout,
        )
        self._check(r, "add comment")

    # ---------- helpers ----------

    def _compose_create_payload(self, d: TicketData) -> Dict[str, Any]:
        """Compose the payload for creating a Bugzilla bug from TicketData."""
        cf = d.custom_fields or {}
        product = str(cf.get("product", self.default_product))
        component = str(cf.get("component", self.default_component))
        version = str(cf.get("version", self.default_version))

        if not product or not component or not version:
            raise ValueError(
                "Bugzilla create requires product, component, and version "
                "(provide defaults or via custom_fields)."
            )

        payload: Dict[str, Any] = {
            "product": product,
            "component": component,
            "version": version,
            "summary": d.title,
            "description": d.description,  # initial comment
        }
        if d.assignee:
            payload["assigned_to"] = d.assignee
        if d.status:
            payload["status"] = self.status_out_map.get(d.status.value, d.status.value)

        for k, v in cf.items():
            if str(k).startswith("cf_"):
                payload[k] = v
        return payload

    def _compose_ticket_data_from_bug(
        self, b: Dict[str, Any], comments: List[Comment]
    ) -> TicketData:
        """Compose TicketData from a Bugzilla bug record and its comments."""
        bz_status = str(b.get("status", "NEW")).upper()
        ours_str = self.status_in_map.get(bz_status, "open")
        try:
            ours = Status(ours_str)
        except Exception:
            ours = Status.OPEN

        return TicketData(
            title=str(b.get("summary", "")),
            description=comments[0].text if comments else "",
            assignee=(b.get("assigned_to") or None),
            requester=(b.get("creator") or None),
            status=ours,
            custom_fields={
                "product": b.get("product"),
                "component": b.get("component"),
                "version": b.get("version"),
                "op_sys": b.get("op_sys"),
                "priority": b.get("priority"),
                "severity": b.get("severity"),
            },
            communication=comments,
        )

    def _check(self, resp: requests.Response, action: str) -> None:
        """Check the HTTP response for errors and raise exceptions as needed."""
        try:
            resp.raise_for_status()
        except requests.HTTPError as e:
            msg = ""
            try:
                j = resp.json()
                msg = j.get("message") or j.get("error") or ""
            except Exception:
                pass
            raise RuntimeError(f"Bugzilla {action} failed: {e} {msg}".strip()) from None
