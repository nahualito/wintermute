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

import hashlib
from pathlib import Path

import pytest

from wintermute.ai.utils import tool_factory
from wintermute.ai.utils.tool_factory import (
    LARGE_PAYLOAD_THRESHOLD_BYTES,
    function_to_tool,
)
from wintermute.utils.blob_manager import (
    BLOB_TYPE,
    WorkspaceManager,
    set_default_workspace,
)


@pytest.fixture()
def workspace(tmp_path: Path) -> WorkspaceManager:
    manager = WorkspaceManager(root=tmp_path / "ws")
    set_default_workspace(manager)
    return manager


def test_save_blob_writes_bytes_with_descriptor(workspace: WorkspaceManager) -> None:
    payload = b"\x00\x01\x02\x03 firmware!"
    descriptor = workspace.save_blob(payload)

    assert descriptor["type"] == BLOB_TYPE
    assert descriptor["size_bytes"] == len(payload)
    assert descriptor["sha256"] == hashlib.sha256(payload).hexdigest()

    file_path = Path(str(descriptor["file_path"]))
    assert file_path.is_file()
    assert file_path.read_bytes() == payload
    assert file_path.parent == workspace.root


def test_save_blob_is_content_addressed(workspace: WorkspaceManager) -> None:
    payload = b"deadbeef" * 64
    first = workspace.save_blob(payload)
    second = workspace.save_blob(payload)

    assert first["file_path"] == second["file_path"]
    assert first["sha256"] == second["sha256"]
    # No duplicate file written.
    matching = list(workspace.root.glob(f"{first['sha256']}*"))
    assert len(matching) == 1


def test_save_blob_encodes_strings(workspace: WorkspaceManager) -> None:
    text = "ünîcödé payload"
    descriptor = workspace.save_blob(text, suffix=".txt")
    file_path = Path(str(descriptor["file_path"]))

    assert file_path.read_bytes() == text.encode("utf-8")
    assert file_path.suffix == ".txt"


def test_save_blob_rejects_unsupported_types(workspace: WorkspaceManager) -> None:
    with pytest.raises(TypeError):
        workspace.save_blob(12345)  # type: ignore[arg-type]


def test_adapter_intercepts_raw_bytes(workspace: WorkspaceManager) -> None:
    flash = b"\xff" * 32  # below threshold but bytes ALWAYS get offloaded

    def dump_flash() -> bytes:
        """Return a fake firmware blob."""
        return flash

    tool = function_to_tool(dump_flash)
    result = tool.handler({})

    assert result["type"] == BLOB_TYPE
    assert result["size_bytes"] == len(flash)
    assert result["sha256"] == hashlib.sha256(flash).hexdigest()
    assert Path(str(result["file_path"])).read_bytes() == flash
    # Critically, the raw bytes are NOT in the LLM-bound payload.
    assert "result" not in result


def test_adapter_intercepts_large_strings(workspace: WorkspaceManager) -> None:
    big_text = "A" * (LARGE_PAYLOAD_THRESHOLD_BYTES + 10)

    def big_dump() -> str:
        """Return a long log."""
        return big_text

    tool = function_to_tool(big_dump)
    result = tool.handler({})

    assert result["type"] == BLOB_TYPE
    assert result["size_bytes"] == len(big_text.encode("utf-8"))
    assert "result" not in result


def test_adapter_passes_small_payloads_through(workspace: WorkspaceManager) -> None:
    def status() -> str:
        """Return a short status string."""
        return "ok"

    tool = function_to_tool(status)
    result = tool.handler({})

    assert result == {"result": "ok"}


def test_adapter_uses_default_workspace(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """function_to_tool must hit the process-wide workspace at call time."""
    fresh = WorkspaceManager(root=tmp_path / "fresh")
    monkeypatch.setattr(tool_factory, "get_default_workspace", lambda: fresh)

    def dump() -> bytes:
        """Tiny dump."""
        return b"hello"

    tool = function_to_tool(dump)
    result = tool.handler({})

    assert Path(str(result["file_path"])).parent == fresh.root
