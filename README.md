# Cerebrum Relay

Secure, opt-in integration sandbox for [Cortex](https://github.com/jacksonjp0311-gif/Cortex). Cerebrum Relay exposes a deliberately small, **read-only** MCP surface over stdio.

It is not part of Cortex, does not ingest files, does not own a database, and never listens on a network socket. Cortex remains the repository-memory authority; Cerebrum only relays explicitly allowlisted requests to an already configured local Cortex installation.

## Security model

- **Deny by default.** A repository name must appear in a local allowlist.
- **Read-only capabilities only.** Status, health, query, and bounded context packets are available. There is no indexing, bootstrapping, migration, decay, self-test, or arbitrary-path tool.
- **Stdio only.** There is no HTTP server, port, or network listener.
- **No secrets in the repository.** Local policy and runtime files are ignored by Git.
- **No private-memory bridge.** Cerebrum does not automatically import journals, conversations, credentials, agent memory, or any other personal data into Cortex.

## Configure

Copy the example policy to a local, untracked location and list only Cortex repository identities you intend to expose:

```powershell
New-Item -ItemType Directory -Force "$HOME/.cerebrum" | Out-Null
Copy-Item policy.example.json "$HOME/.cerebrum/policy.json"
```

Edit `allowed_repositories` to use the repository names already registered in Cortex. Optionally set `CEREBRUM_POLICY` to another absolute policy path and `CEREBRUM_CORTEX_HOME` to the Cortex home directory.

## Run

```powershell
python cerebrum_relay.py
```

Configure an MCP client to launch that command over stdio. The exposed tools are `cerebrum_status`, `cerebrum_health`, `cerebrum_query`, and `cerebrum_context`.

## Development

```powershell
python -m unittest discover -s tests -v
```

The first release is intentionally narrow. Any future maintenance capability must be a separate, explicitly authorized design—not an expansion of this read surface.
