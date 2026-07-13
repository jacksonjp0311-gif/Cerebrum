# Cerebrum Relay

Secure, opt-in integration sandbox for [Cortex](https://github.com/jacksonjp0311-gif/Cortex). Cerebrum Relay exposes a deliberately small, **read-only** MCP surface over stdio.

It is not part of Cortex, does not ingest files, does not own a database, and never listens on a network socket. Cortex remains the repository-memory authority; Cerebrum only relays explicitly allowlisted requests to an already configured local Cortex installation.

## Security model

- **Deny by default.** A repository name must appear in a local allowlist.
- **Read-only capabilities only.** Status, health, query, and bounded context packets are available. There is no indexing, bootstrapping, migration, decay, self-test, or arbitrary-path tool.
- **Stdio only.** There is no HTTP server, port, or network listener.
- **No secrets in the repository.** Local policy and runtime files are ignored by Git.
- **No private-memory bridge.** Cerebrum does not automatically import journals, conversations, credentials, agent memory, or any other personal data into Cortex.

## Phoenix integration boundary

The Phoenix adapter (`phoenix_adapter.py`) adds two tools — `cerebrum_phoenix_audit` and `cerebrum_phoenium_context` — that expose a **strictly filtered** view of a Phoenix project directory. The boundary is hardcoded and cannot be weakened by configuration.

### Always denied (hardcoded)

| Pattern | Reason |
|---|---|
| `**/SOUL.md`, `**/JOURNAL.md`, `**/MEMORY.md` | Core identity & memory |
| `**/IDENTITY.md`, `**/AGENTS.md`, `**/ACTIVE_TASKS.md` | Operational identity |
| `**/memory/**`, `**/phone_sessions/**`, `**/sessions/**` | Private memory directories |
| `**/PRE_COMPRESSION*` | Pre-compression notes |
| `**/.env*`, `**/*credential*`, `**/*api_key*`, `**/*secret*`, `**/*token*` | Credentials |
| `**/*conversation*`, `**/*chat*`, `**/*transcript*` | Conversation archives |
| `**/*relationship*`, `**/*personal*` | Personal data |

### Allowed

| Type | Condition |
|---|---|
| Source code (`.py`, `.rs`, `.ts`, `.kt`, etc.) | Anywhere not denied |
| Schemas (`.json`, `.proto`, `.yaml`, `.toml`) | Anywhere not denied |
| Markdown / text docs | Only under `docs/`, `tests/`, `examples/`, or root-level `README`/`CHANGELOG`/`LICENSE` |
| Operational logs (`.log`) | Only when `phoenix_allow_logs: true` is explicitly set |

### Tools

- **`cerebrum_phoenix_audit`** — Dry-run: lists every file with its allow/deny classification. Does not read contents. Use this to verify the boundary before enabling ingestion.
- **`cerebrum_phoenix_context`** — Reads allowed files (up to 2 MB total, 256 KB per file) and returns a context packet. Denied files are counted but never read.

## Configure

Copy the example policy to a local, untracked location and list only Cortex repository identities you intend to expose:

```powershell
New-Item -ItemType Directory -Force "$HOME/.cerebrum" | Out-Null
Copy-Item policy.example.json "$HOME/.cerebrum/policy.json"
```

Edit `allowed_repositories` to use the repository names already registered in Cortex. Optionally set `CEREBRUM_POLICY` to another absolute policy path and `CEREBRUM_CORTEX_HOME` to the Cortex home directory.

To enable Phoenix integration, set `phoenix_root` to the absolute path of your Phoenix project directory:

```json
{
  "allowed_repositories": ["my-repo"],
  "phoenix_root": "/home/user/.phoenix/phoenix_v2",
  "phoenix_allow_logs": false
}
```

## Run

```powershell
python cerebrum_relay.py
```

Configure an MCP client to launch that command over stdio. The exposed tools are `cerebrum_status`, `cerebrum_health`, `cerebrum_query`, `cerebrum_context`, `cerebrum_phoenix_audit`, and `cerebrum_phoenix_context`.

## Development

```powershell
python -m unittest discover -s tests -v
```

The first release is intentionally narrow. Any future maintenance capability must be a separate, explicitly authorized design—not an expansion of this read surface.
