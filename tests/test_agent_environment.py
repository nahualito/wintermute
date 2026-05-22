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

"""Tests for the first-run bundled-profile seeding logic.

`init_agent_environment` ships with `pip install wintermute` and runs on
console startup. These tests exercise the contract:

* a fresh ~/.wintermute/agentic/profiles tree gets populated with every
  bundled `.md` file;
* user-edited files are NEVER overwritten on subsequent calls;
* the function tolerates a non-existent target tree (creates it);
* the function is safe to invoke when the bundled package cannot be
  located (logs a warning, returns empty list).
"""

from __future__ import annotations

import importlib.resources
from pathlib import Path
from typing import List

import pytest

from wintermute.ai.agent import (
    DEFAULT_IMPLEMENTATIONS_DIR,
    DEFAULT_PROFILES_DIR,
    init_agent_environment,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bundled_profile_names() -> List[str]:
    """Read the bundled .md names directly from the package so this test
    stays in lockstep with whatever profiles ship in the wheel."""
    return sorted(
        r.name
        for r in importlib.resources.files("wintermute.data.agent_profiles").iterdir()
        if r.name.endswith(".md")
    )


# ---------------------------------------------------------------------------
# Fresh-install behaviour with Path.home() redirected to tmp_path
# ---------------------------------------------------------------------------


def test_init_seeds_empty_home_with_all_bundled_profiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mock `Path.home()` to a tmp dir and confirm every bundled profile
    is copied into ~/.wintermute/agentic/profiles/."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    # The module-level constants were resolved at import time using the
    # real Path.home(). Re-derive them against the mocked tmp_path so
    # init_agent_environment() lands in the sandbox rather than the real
    # operator's home directory.
    fake_profiles = tmp_path / ".wintermute" / "agentic" / "profiles"
    fake_impls = tmp_path / ".wintermute" / "agentic" / "implementations"

    copied = init_agent_environment(
        profiles_dir=fake_profiles, implementations_dir=fake_impls
    )

    expected = _bundled_profile_names()
    assert expected, "no bundled profiles found — packaging is broken"

    # Every bundled file landed in the seeded directory.
    landed = sorted(p.name for p in fake_profiles.glob("*.md"))
    assert landed == expected

    # All of them were freshly copied this run.
    assert sorted(p.name for p in copied) == expected

    # Implementations directory was created (empty).
    assert fake_impls.is_dir()
    assert list(fake_impls.iterdir()) == []


def test_init_creates_missing_parent_directories(tmp_path: Path) -> None:
    deep_target = tmp_path / "x" / "y" / "z" / "profiles"
    deep_impls = tmp_path / "x" / "y" / "z" / "impls"
    assert not deep_target.exists()
    assert not deep_impls.exists()

    init_agent_environment(profiles_dir=deep_target, implementations_dir=deep_impls)
    assert deep_target.is_dir()
    assert deep_impls.is_dir()
    assert any(deep_target.glob("*.md"))


# ---------------------------------------------------------------------------
# Idempotency / no-clobber behaviour
# ---------------------------------------------------------------------------


def test_init_does_not_overwrite_user_edits(tmp_path: Path) -> None:
    """If a user has already edited a profile, a subsequent seed run
    must not touch it."""
    profiles = tmp_path / "profiles"
    impls = tmp_path / "impls"
    profiles.mkdir()
    impls.mkdir()

    # Pick the first bundled profile name and pre-write a user edit.
    name = _bundled_profile_names()[0]
    user_edit = "---\nname: user_owned\n---\nDO NOT TOUCH\n"
    (profiles / name).write_text(user_edit, encoding="utf-8")

    copied = init_agent_environment(profiles_dir=profiles, implementations_dir=impls)

    # The user's file content is intact.
    assert (profiles / name).read_text(encoding="utf-8") == user_edit
    # The seeder did NOT count it as copied.
    assert (profiles / name) not in copied
    # Other bundled profiles still got seeded.
    other_bundled = [n for n in _bundled_profile_names() if n != name]
    landed = sorted(p.name for p in profiles.glob("*.md") if p.name != name)
    assert landed == sorted(other_bundled)


def test_init_is_idempotent_on_second_run(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    impls = tmp_path / "impls"

    first = init_agent_environment(profiles_dir=profiles, implementations_dir=impls)
    second = init_agent_environment(profiles_dir=profiles, implementations_dir=impls)

    assert len(first) == len(_bundled_profile_names())
    assert second == []  # second run is a no-op


# ---------------------------------------------------------------------------
# Default-argument path: uses module-level constants when no kwargs given
# ---------------------------------------------------------------------------


def test_init_defaults_use_path_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No-kwargs call must seed under the *module-level* DEFAULT_*_DIR.
    We monkey-patch those constants (rather than Path.home itself) to
    redirect the seed without touching the operator's real home dir.
    """
    fake_profiles = tmp_path / "profiles"
    fake_impls = tmp_path / "impls"
    monkeypatch.setattr("wintermute.ai.agent.DEFAULT_PROFILES_DIR", fake_profiles)
    monkeypatch.setattr("wintermute.ai.agent.DEFAULT_IMPLEMENTATIONS_DIR", fake_impls)

    copied = init_agent_environment()
    assert copied, "default-arg call did not seed any files"
    assert sorted(p.name for p in copied) == _bundled_profile_names()


# ---------------------------------------------------------------------------
# Real defaults exist and point under Path.home()
# ---------------------------------------------------------------------------


def test_default_dirs_are_under_path_home() -> None:
    """Sanity check on the module-level constants — they must be rooted
    under the user's home, not somewhere global like /etc/."""
    home = Path.home()
    assert home in DEFAULT_PROFILES_DIR.parents
    assert home in DEFAULT_IMPLEMENTATIONS_DIR.parents


# ---------------------------------------------------------------------------
# Failure resilience — should never throw to the caller
# ---------------------------------------------------------------------------


def test_init_handles_missing_bundled_package_gracefully(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the bundled package cannot be located, the function must log a
    warning and return an empty list — startup must not crash."""
    monkeypatch.setattr(
        "wintermute.ai.agent._BUNDLED_PROFILES_PACKAGE",
        "wintermute.data.does_not_exist",
    )
    copied = init_agent_environment(
        profiles_dir=tmp_path / "p", implementations_dir=tmp_path / "i"
    )
    assert copied == []
    # The target dirs were still created defensively.
    assert (tmp_path / "p").is_dir()
    assert (tmp_path / "i").is_dir()
