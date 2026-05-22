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

"""File-driven autonomous worker agent.

The :class:`WorkerAgent` is the workhorse of Wintermute's multi-agent
architecture (Phase 2 of ``AGENT_REFACTOR_PLAN.md``). Each agent is
configured by two markdown files on disk:

* ``~/.wintermute/agentic/profiles/<name>.md`` — persona, system prompt,
  allowed tool names, optional preferred model. Parsed via a tiny
  YAML-ish frontmatter reader so we do not pull in PyYAML.
* ``~/.wintermute/agentic/implementations/<file>.md`` — the step-by-step
  task description the agent will execute autonomously.

Architectural constraints enforced here (per the refactor plan):

1. **Isolated registries.** An agent NEVER reaches into
   :data:`wintermute.ai.tools_runtime.tools`. Tools must be explicitly
   registered on the instance with :meth:`register_tool`. This keeps
   per-agent toolsurfaces small (e.g. Ghidra tools stay with the reverse
   engineer agent) and prevents context collapse across agents.
2. **Dataclass bypass for assistant ``tool_calls``.**
   :class:`wintermute.ai.types.Message` is ``frozen=True``. To attach the
   provider-shaped ``tool_calls`` payload to the assistant turn so that
   LiteLLM sees it on the next request, we use ``object.__setattr__``.
3. **Argument-shape split.** LiteLLM requires ``tool_calls[*].function.
   arguments`` in the conversation history to be a stringified JSON
   payload, while the tool handler we invoke locally expects a parsed
   ``dict``. This module handles that split in one place.
"""

from __future__ import annotations

import importlib.resources
import inspect
import json
import logging
from pathlib import Path
from typing import Any, Awaitable, Dict, List, Optional, Tuple, Union, cast

from .json_types import JSONObject
from .provider import Router
from .tools_runtime import Tool
from .types import ChatRequest, Message, ToolSpec

log = logging.getLogger(__name__)

# Package that ships the bundled default profiles (see
# pyproject.toml: tool.hatch.build.targets.wheel.force-include).
_BUNDLED_PROFILES_PACKAGE = "wintermute.data.agent_profiles"


# ---------------------------------------------------------------------------
# Minimal frontmatter parser
# ---------------------------------------------------------------------------


def _parse_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
    """Parse a tiny YAML-ish ``---`` frontmatter block.

    Supports ``key: value`` scalars and a block form for lists:

        tools:
          - ghidra__decompile
          - ghidra__list_functions

    No quotes, nesting, or anchors. If the document does not begin with a
    ``---`` fence the whole text is treated as the body and an empty meta
    dict is returned.
    """
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text

    end_idx: Optional[int] = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end_idx = i
            break
    if end_idx is None:
        return {}, text

    meta: Dict[str, Any] = {}
    current_list_key: Optional[str] = None
    for raw in lines[1:end_idx]:
        if not raw.strip():
            continue
        stripped = raw.lstrip()
        # List item belonging to the most recent `key:` with no inline value.
        if raw.startswith((" ", "\t")) and stripped.startswith("- "):
            if current_list_key is None:
                continue
            meta[current_list_key].append(stripped[2:].strip())
            continue
        if ":" not in stripped:
            current_list_key = None
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if value:
            meta[key] = value
            current_list_key = None
        else:
            meta[key] = []
            current_list_key = key

    body = "\n".join(lines[end_idx + 1 :])
    return meta, body


# ---------------------------------------------------------------------------
# WorkerAgent
# ---------------------------------------------------------------------------


DEFAULT_PROFILES_DIR: Path = Path.home() / ".wintermute" / "agentic" / "profiles"
DEFAULT_IMPLEMENTATIONS_DIR: Path = (
    Path.home() / ".wintermute" / "agentic" / "implementations"
)


def init_agent_environment(
    *,
    profiles_dir: Optional[Path] = None,
    implementations_dir: Optional[Path] = None,
) -> List[Path]:
    """Seed ~/.wintermute/agentic/ with the bundled default agent profiles.

    Intended to be called once on console startup. Idempotent: profiles
    that already exist on disk are preserved as-is so a user's local
    edits are never clobbered. Returns the list of files actually
    copied this invocation (empty list when everything was already
    present, which is the steady-state result).

    Both target directories are created if missing. The profiles come
    from the ``wintermute.data.agent_profiles`` package, which ships
    every ``*.md`` profile authored in Phase 5.
    """
    target_profiles = profiles_dir or DEFAULT_PROFILES_DIR
    target_impls = implementations_dir or DEFAULT_IMPLEMENTATIONS_DIR

    target_profiles.mkdir(parents=True, exist_ok=True)
    target_impls.mkdir(parents=True, exist_ok=True)

    copied: List[Path] = []
    try:
        package_root = importlib.resources.files(_BUNDLED_PROFILES_PACKAGE)
    except (ModuleNotFoundError, FileNotFoundError) as exc:
        log.warning(
            "Bundled agent profiles package not importable (%s); "
            "skipping first-run seeding",
            exc,
        )
        return copied

    for resource in package_root.iterdir():
        name = resource.name
        if not name.endswith(".md"):
            continue
        destination = target_profiles / name
        if destination.exists():
            # Respect user edits — once a profile lives on disk we never
            # overwrite it. Operators can delete a file to re-seed it.
            continue
        try:
            content = resource.read_text(encoding="utf-8")
        except (OSError, FileNotFoundError) as exc:
            log.warning("Failed to read bundled profile %s: %s", name, exc)
            continue
        try:
            destination.write_text(content, encoding="utf-8")
        except OSError as exc:
            log.warning("Failed to seed profile %s at %s: %s", name, destination, exc)
            continue
        copied.append(destination)
    return copied


class WorkerAgent:
    """Autonomous markdown-driven worker with an isolated tool registry."""

    def __init__(
        self,
        router: Router,
        *,
        profiles_dir: Optional[Path] = None,
        implementations_dir: Optional[Path] = None,
        max_iterations: int = 25,
    ) -> None:
        self.router = router
        self.profiles_dir = profiles_dir or DEFAULT_PROFILES_DIR
        self.implementations_dir = implementations_dir or DEFAULT_IMPLEMENTATIONS_DIR
        self.max_iterations = max_iterations

        # Profile-driven state, populated by load_profile().
        self.name: str = ""
        self.description: str = ""
        self.system_prompt: str = ""
        self.allowed_tools: List[str] = []
        self.model: Optional[str] = None

        # Implementation body, populated by load_implementation().
        self.implementation: str = ""

        # ISOLATED local tool registry. NEVER touched by the global registry.
        self._tools: Dict[str, Tool] = {}

        # Conversation transcript from the most recent run().
        self.transcript: List[Message] = []

    # -- public registry api -------------------------------------------------

    def register_tool(self, tool: Tool) -> None:
        """Register a tool in this agent's isolated registry.

        Tools must be registered explicitly per-agent — there is no global
        fallthrough. This is the mechanism that keeps Ghidra tools out of
        the JTAG specialist's context, and vice versa.
        """
        self._tools[tool.name] = tool

    def unregister_tool(self, name: str) -> bool:
        return self._tools.pop(name, None) is not None

    def list_tools(self) -> List[str]:
        return list(self._tools.keys())

    # -- loading -------------------------------------------------------------

    def load_profile(self, name: str, *, profiles_dir: Optional[Path] = None) -> None:
        """Load persona/system-prompt/tool-allowlist from a profile markdown.

        Reads ``<profiles_dir>/<name>.md``. Frontmatter recognised keys:

        * ``name`` — human-readable agent name (defaults to ``name`` arg).
        * ``description`` — short summary, useful for the supervisor's UI.
        * ``tools`` — list of tool names this agent is permitted to call.
        * ``model`` — optional preferred model override.

        The body of the markdown becomes the system prompt verbatim.
        """
        directory = profiles_dir or self.profiles_dir
        path = directory / f"{name}.md"
        if not path.is_file():
            raise FileNotFoundError(f"Profile {name!r} not found at {path}")

        text = path.read_text(encoding="utf-8")
        meta, body = _parse_frontmatter(text)

        self.name = str(meta.get("name", name))
        self.description = str(meta.get("description", ""))
        self.system_prompt = body.strip()
        raw_tools = meta.get("tools", []) or []
        self.allowed_tools = [str(t) for t in raw_tools]
        self.model = str(meta["model"]) if "model" in meta and meta["model"] else None

    def load_implementation(
        self,
        path: Union[str, Path],
        *,
        implementations_dir: Optional[Path] = None,
    ) -> None:
        """Read the agent's step-by-step execution plan.

        Relative paths are resolved against ``implementations_dir`` (which
        defaults to ``~/.wintermute/agentic/implementations``). Absolute
        paths are taken as-is so a supervisor can hand in a freshly
        generated plan from anywhere.
        """
        p = Path(path)
        if not p.is_absolute():
            directory = implementations_dir or self.implementations_dir
            p = directory / p
        if not p.is_file():
            raise FileNotFoundError(f"Implementation file not found at {p}")
        self.implementation = p.read_text(encoding="utf-8").strip()

    # -- helpers -------------------------------------------------------------

    def _build_tool_specs(self) -> List[ToolSpec]:
        """Build ToolSpecs for the intersection of allowed_tools and the
        isolated registry. Unknown allowlist entries are silently dropped
        — the agent simply will not advertise tools it does not have.
        """
        specs: List[ToolSpec] = []
        for tname in self.allowed_tools:
            tool = self._tools.get(tname)
            if tool is None:
                log.debug(
                    "Agent %r allow-lists tool %r but it is not registered locally",
                    self.name,
                    tname,
                )
                continue
            specs.append(
                ToolSpec(
                    name=tool.name,
                    description=tool.description,
                    input_schema=tool.input_schema,
                    output_schema=tool.output_schema,
                )
            )
        return specs

    @staticmethod
    def _stringify_arguments(arguments: Any) -> str:
        """Return JSON-string form for LiteLLM history.

        LiteLLM (and the underlying provider APIs) expect
        ``tool_calls[*].function.arguments`` to be a JSON-stringified
        payload, NOT a parsed object. Providers in this codebase
        sometimes hand us the already-stringified form (via litellm),
        sometimes the parsed dict — handle both.
        """
        if isinstance(arguments, str):
            return arguments
        return json.dumps(arguments)

    @staticmethod
    def _parse_arguments(arguments: Any) -> Dict[str, Any]:
        """Return parsed-dict form for local tool invocation.

        MCP ``call_tool`` and Wintermute's :class:`Tool` handlers expect
        a real :class:`dict`. If we receive a JSON string, parse it; if
        parsing fails we fall back to ``{}`` rather than crashing the
        whole loop on a malformed assistant turn.
        """
        if isinstance(arguments, str):
            try:
                parsed = json.loads(arguments) if arguments else {}
            except json.JSONDecodeError:
                log.warning("Tool arguments were not valid JSON: %r", arguments)
                return {}
            return parsed if isinstance(parsed, dict) else {}
        if isinstance(arguments, dict):
            return dict(arguments)
        return {}

    async def _invoke_tool(self, name: str, args: Dict[str, Any]) -> str:
        """Run a tool from the isolated registry. Async or sync handlers
        are both supported; return value is coerced to a string for the
        ``tool`` role message.
        """
        tool = self._tools.get(name)
        if tool is None:
            return json.dumps(
                {"error": f"Tool {name!r} is not registered with this agent."}
            )
        try:
            result = tool.handler(cast(JSONObject, args))
            if inspect.isawaitable(result):
                result = await cast(Awaitable[Any], result)
        except Exception as exc:  # noqa: BLE001 — surface to LLM, do not crash loop
            log.exception("Tool %r raised during agent run", name)
            return json.dumps({"error": f"Tool {name!r} raised: {exc}"})
        if isinstance(result, str):
            return result
        try:
            return json.dumps(result)
        except (TypeError, ValueError):
            return str(result)

    # -- run -----------------------------------------------------------------

    async def run(self) -> str:
        """Execute the autonomous tool-calling loop.

        Loop semantics:

        1. Ask the LLM for the next turn given the current history.
        2. If the LLM returns no tool calls, return its content — done.
        3. Otherwise: append the assistant turn (with ``tool_calls``
           attached via the dataclass bypass), execute each tool from
           the isolated registry, and append each result as a
           ``role="tool"`` message.
        4. Repeat, bounded by :attr:`max_iterations` as a safety net so
           a runaway model cannot loop forever.

        Returns the final assistant content (or a sentinel string if we
        ran out of iterations).
        """
        if not self.system_prompt:
            raise RuntimeError(
                "WorkerAgent has no profile loaded; call load_profile() first"
            )
        if not self.implementation:
            raise RuntimeError(
                "WorkerAgent has no implementation loaded; call load_implementation() first"
            )

        messages: List[Message] = [
            Message(role="system", content=self.system_prompt),
            Message(role="user", content=self.implementation),
        ]
        tool_specs = self._build_tool_specs()

        iteration = 0
        while True:
            if iteration >= self.max_iterations:
                log.warning(
                    "WorkerAgent %r hit max_iterations=%d without finishing",
                    self.name,
                    self.max_iterations,
                )
                self.transcript = list(messages)
                return (
                    "[WorkerAgent] Iteration cap reached "
                    f"({self.max_iterations}) before the agent produced a final answer."
                )
            iteration += 1

            req = ChatRequest(
                messages=messages,
                tools=tool_specs if tool_specs else None,
                model=self.model,
                tool_choice="auto" if tool_specs else "none",
            )
            provider, chosen = self.router.choose(req)
            resp = provider.chat(chosen)

            if not resp.tool_calls:
                messages.append(Message(role="assistant", content=resp.content or ""))
                self.transcript = list(messages)
                return resp.content or ""

            # Build the assistant turn and attach the provider-shaped
            # tool_calls list. We MUST use object.__setattr__ because
            # Message is a frozen dataclass — any other setattr raises
            # FrozenInstanceError.
            formatted_tool_calls = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.name,
                        # LiteLLM requires the stringified form here.
                        "arguments": self._stringify_arguments(tc.arguments),
                    },
                }
                for tc in resp.tool_calls
            ]
            assistant_msg = Message(role="assistant", content=resp.content or "")
            object.__setattr__(assistant_msg, "tool_calls", formatted_tool_calls)
            messages.append(assistant_msg)

            # Execute every tool call sequentially. Parsed-dict form here.
            for tc in resp.tool_calls:
                parsed_args = self._parse_arguments(tc.arguments)
                tool_output = await self._invoke_tool(tc.name, parsed_args)
                messages.append(
                    Message(
                        role="tool",
                        content=tool_output,
                        tool_name=tc.name,
                        tool_call_id=tc.id,
                    )
                )


__all__ = [
    "DEFAULT_IMPLEMENTATIONS_DIR",
    "DEFAULT_PROFILES_DIR",
    "WorkerAgent",
    "_parse_frontmatter",
    "init_agent_environment",
]
