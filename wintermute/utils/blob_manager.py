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
import logging
import os
import threading
from pathlib import Path
from typing import Dict, Final, Union

log = logging.getLogger(__name__)

DEFAULT_WORKSPACE_DIR: Final[str] = "./wintermute_workspace"
WORKSPACE_ENV_VAR: Final[str] = "WINTERMUTE_WORKSPACE_ROOT"
BLOB_TYPE: Final[str] = "binary_blob"


class WorkspaceManager:
    """Manages a local directory used to offload binary artifacts.

    Tools that produce firmware dumps, memory captures, or otherwise large
    payloads write the bytes to disk through this manager and hand back a
    compact descriptor to the LLM. This keeps multi-megabyte blobs out of
    the model's context window while preserving an addressable handle the
    LLM (or the human operator) can pass to follow-up tools.
    """

    def __init__(self, root: Union[str, Path, None] = None) -> None:
        chosen = root or os.getenv(WORKSPACE_ENV_VAR) or DEFAULT_WORKSPACE_DIR
        self.root: Path = Path(chosen).expanduser().resolve()
        self._lock = threading.Lock()
        self._ensure_root()

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def save_blob(
        self,
        data: Union[bytes, bytearray, memoryview, str],
        *,
        suffix: str = ".bin",
    ) -> Dict[str, Union[str, int]]:
        """Persist ``data`` to the workspace and return its descriptor.

        Strings are encoded as UTF-8. The filename is content-addressed by
        SHA-256, so identical payloads collapse to a single file on disk.
        """
        if isinstance(data, str):
            payload = data.encode("utf-8")
        elif isinstance(data, (bytearray, memoryview)):
            payload = bytes(data)
        elif isinstance(data, bytes):
            payload = data
        else:
            raise TypeError(
                f"WorkspaceManager.save_blob expects bytes-like or str, got {type(data).__name__}"
            )

        sha256 = self._digest(payload)
        filename = f"{sha256}{suffix}"
        target = self.root / filename

        with self._lock:
            self._ensure_root()
            if not target.exists():
                tmp = target.with_suffix(target.suffix + ".part")
                tmp.write_bytes(payload)
                os.replace(tmp, target)

        log.info(
            "WorkspaceManager stored %d bytes at %s (sha256=%s)",
            len(payload),
            target,
            sha256,
        )

        return {
            "file_path": str(target),
            "size_bytes": len(payload),
            "sha256": sha256,
            "type": BLOB_TYPE,
        }

    def register_file(
        self,
        path: Union[str, Path],
        *,
        suffix: Union[str, None] = None,
    ) -> Dict[str, Union[str, int]]:
        """Adopt an existing file into the workspace and return its descriptor.

        The file is hashed in chunks (so multi-gigabyte firmware dumps never
        get loaded into Python memory) and then renamed into a content-
        addressed slot under :attr:`root`. If a file with the same digest is
        already present, the source is removed and the existing target is
        kept. Tools that stream output directly to disk (for example,
        OpenOCD's ``dump_image``) should produce their temporary file inside
        :attr:`root` so this rename stays on a single filesystem.

        Args:
            path: Path to the file to adopt.
            suffix: Optional suffix to append to the SHA-256 digest when
                naming the target. Defaults to the source file's suffix or
                ``.bin`` when none is present.

        Returns:
            A descriptor matching :meth:`save_blob` (``file_path``,
            ``size_bytes``, ``sha256``, ``type``).

        Raises:
            FileNotFoundError: If ``path`` does not exist or is not a file.
        """
        src = Path(path).expanduser().resolve()
        if not src.is_file():
            raise FileNotFoundError(f"File to register does not exist: {src}")

        sha = hashlib.sha256()
        size = 0
        with src.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                sha.update(chunk)
                size += len(chunk)

        digest = sha.hexdigest()
        chosen_suffix = suffix if suffix is not None else (src.suffix or ".bin")
        target = self.root / f"{digest}{chosen_suffix}"

        with self._lock:
            self._ensure_root()
            if target.exists():
                if src != target:
                    src.unlink(missing_ok=True)
            else:
                os.replace(src, target)

        log.info(
            "WorkspaceManager registered %s as %s (sha256=%s, size=%d)",
            src,
            target,
            digest,
            size,
        )

        return {
            "file_path": str(target),
            "size_bytes": size,
            "sha256": digest,
            "type": BLOB_TYPE,
        }


_default_manager: WorkspaceManager | None = None
_default_lock = threading.Lock()


def get_default_workspace() -> WorkspaceManager:
    """Return a process-wide WorkspaceManager, creating it on first use."""
    global _default_manager
    if _default_manager is None:
        with _default_lock:
            if _default_manager is None:
                _default_manager = WorkspaceManager()
    return _default_manager


def set_default_workspace(manager: WorkspaceManager) -> None:
    """Override the process-wide WorkspaceManager (useful for tests)."""
    global _default_manager
    with _default_lock:
        _default_manager = manager


__all__ = [
    "BLOB_TYPE",
    "DEFAULT_WORKSPACE_DIR",
    "WORKSPACE_ENV_VAR",
    "WorkspaceManager",
    "get_default_workspace",
    "set_default_workspace",
]
