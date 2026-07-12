"""Cerebrum Relay: an allowlisted, read-only Cortex MCP adapter over stdio."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_RESPONSE_BYTES = 256_000
READ_TOOLS = {
    "cerebrum_status": ("status", True),
    "cerebrum_health": ("health", True),
    "cerebrum_query": ("query", True),
    "cerebrum_context": ("context", True),
}


@dataclass(frozen=True)
class Policy:
    allowed_repositories: frozenset[str]
    max_query_characters: int = 2000
    max_results: int = 10
    command_timeout_seconds: int = 20


def policy_path() -> Path:
    configured = os.environ.get("CEREBRUM_POLICY")
    return Path(configured).expanduser() if configured else Path.home() / ".cerebrum" / "policy.json"


def load_policy(path: Path | None = None) -> Policy:
    source = path or policy_path()
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Cerebrum policy is unavailable or invalid") from exc
    repos = raw.get("allowed_repositories", [])
    if not isinstance(repos, list) or not all(isinstance(repo, str) and repo for repo in repos):
        raise ValueError("Policy allowlist is invalid")
    return Policy(
        allowed_repositories=frozenset(repos),
        max_query_characters=_bounded_int(raw.get("max_query_characters", 2000), 1, 10_000),
        max_results=_bounded_int(raw.get("max_results", 10), 1, 25),
        command_timeout_seconds=_bounded_int(raw.get("command_timeout_seconds", 20), 1, 60),
    )


def _bounded_int(value: Any, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ValueError("Policy value is outside safe bounds")
    return value


def cortex_command() -> list[str]:
    """Return the fixed local Cortex launcher; request data never controls this."""
    command = os.environ.get("CEREBRUM_CORTEX_PYTHON", sys.executable)
    return [command, "-m", "cortex"]


def execute_cortex(arguments: list[str], timeout: int) -> dict[str, Any]:
    command = cortex_command()
    home = os.environ.get("CEREBRUM_CORTEX_HOME")
    if home:
        command.extend(["--home", home])
    command.extend(arguments)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Cortex command could not complete") from exc
    if completed.returncode != 0:
        raise RuntimeError("Cortex rejected the request")
    output = completed.stdout.encode("utf-8")[:MAX_RESPONSE_BYTES].decode("utf-8", errors="ignore")
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Cortex returned an invalid response") from exc


def _allowed_repo(arguments: dict[str, Any], policy: Policy) -> str:
    repo = arguments.get("repo_name")
    if not isinstance(repo, str) or repo not in policy.allowed_repositories:
        raise PermissionError("Repository is not allowlisted")
    return repo


def handle_tool_call(name: str, arguments: dict[str, Any], policy: Policy) -> dict[str, Any]:
    if name not in READ_TOOLS:
        raise PermissionError("Tool is not available")
    command_name, needs_repo = READ_TOOLS[name]
    cli_args = [command_name]
    if needs_repo:
        repo = _allowed_repo(arguments, policy)
        cli_args.extend(["--repo", repo])
    if name in {"cerebrum_query", "cerebrum_context"}:
        field = "query" if name == "cerebrum_query" else "task"
        text = arguments.get(field)
        if not isinstance(text, str) or not text.strip() or len(text) > policy.max_query_characters:
            raise ValueError(f"{field} is invalid")
        if name == "cerebrum_query":
            limit = arguments.get("limit", policy.max_results)
            if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= policy.max_results:
                raise ValueError("limit is invalid")
            cli_args.extend([text, "--limit", str(limit)])
        else:
            cli_args.extend(["--task", text])
    cli_args.append("--json")
    return execute_cortex(cli_args, policy.command_timeout_seconds)


def tool_schemas() -> list[dict[str, Any]]:
    return [
        {"name": "cerebrum_status", "description": "Read status for an allowlisted Cortex repository.", "inputSchema": {"type": "object", "properties": {"repo_name": {"type": "string"}}, "required": ["repo_name"]}},
        {"name": "cerebrum_health", "description": "Read health for an allowlisted Cortex repository.", "inputSchema": {"type": "object", "properties": {"repo_name": {"type": "string"}}, "required": ["repo_name"]}},
        {"name": "cerebrum_query", "description": "Query an allowlisted Cortex repository without indexing or changing it.", "inputSchema": {"type": "object", "properties": {"repo_name": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["repo_name", "query"]}},
        {"name": "cerebrum_context", "description": "Read a bounded context packet from an allowlisted Cortex repository.", "inputSchema": {"type": "object", "properties": {"repo_name": {"type": "string"}, "task": {"type": "string"}}, "required": ["repo_name", "task"]}},
    ]


def handle_request(request: dict[str, Any], policy: Policy) -> dict[str, Any] | None:
    request_id = request.get("id")
    method = request.get("method")
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        result: dict[str, Any] = {"protocolVersion": "2024-11-05", "serverInfo": {"name": "cerebrum-relay", "version": "0.1.0"}, "capabilities": {"tools": {}}}
    elif method == "tools/list":
        result = {"tools": tool_schemas()}
    elif method == "tools/call":
        params = request.get("params", {})
        try:
            data = handle_tool_call(params.get("name", ""), params.get("arguments", {}), policy)
            result = {"content": [{"type": "text", "text": json.dumps(data, sort_keys=True)}], "isError": False}
        except (PermissionError, ValueError, RuntimeError):
            result = {"content": [{"type": "text", "text": "Request denied or unavailable."}], "isError": True}
    else:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main() -> int:
    try:
        policy = load_policy()
    except ValueError:
        print("Cerebrum requires a valid local policy file.", file=sys.stderr)
        return 2
    for line in sys.stdin:
        try:
            request = json.loads(line)
            response = handle_request(request, policy)
            if response is not None:
                sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            sys.stdout.write('{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}\n')
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
