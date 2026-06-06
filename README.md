# fipsign-mcp

[![PyPI](https://img.shields.io/pypi/v/fipsign-mcp)](https://pypi.org/project/fipsign-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204-blue)](https://csrc.nist.gov/pubs/fips/204/final)

MCP server for [FIPSign](https://fipsign.dev) — post-quantum digital signing via **ML-DSA-65** (NIST FIPS 204).

Gives Claude Desktop, Claude Code, and any MCP-compatible AI agent full access to the FIPSign API without writing code: sign payloads, verify tokens, issue and revoke post-quantum certificates, manage webhooks, and monitor usage.

---

## Tools

| Tool | Description | Token cost |
|---|---|---|
| `fipsign_health` | Check service status | free |
| `fipsign_public_key` | Get the server's ML-DSA-65 public key | free |
| `fipsign_sign` | Sign any payload | 1 token |
| `fipsign_verify` | Verify a signed token | 1 token |
| `fipsign_revoke` | Permanently revoke a token | 1 token |
| `fipsign_usage` | Get token balance and usage history | free |
| `fipsign_generate_key_pair` | Generate an ML-DSA-65 key pair locally | free |
| `fipsign_ca_issue` | Issue a post-quantum certificate | 1 token |
| `fipsign_ca_revoke_cert` | Revoke a certificate | 1 token |
| `fipsign_ca_get_cert` | Get certificate status by ID | free |
| `fipsign_ca_get_crl` | Get the Certificate Revocation List | free |
| `fipsign_webhooks_register` | Register a webhook endpoint | free |
| `fipsign_webhooks_get` | Get current webhook config | free |
| `fipsign_webhooks_delete` | Delete webhook configuration | free |
| `fipsign_webhooks_test` | Send a test event to your webhook | free |

---

## Prerequisites

1. Python 3.10 or later
2. A FIPSign account and API key — [create one free at app.fipsign.dev](https://app.fipsign.dev)
3. For CA tools: a CA created inside your project from the dashboard

---

## Local testing before publishing

### Level 1 — MCP Inspector (no Claude Desktop required)

The Inspector opens a browser UI where you can call each tool manually and inspect responses without Claude Desktop.

```bash
git clone https://github.com/fipsign/fipsign-mcp-python
cd fipsign-mcp-python
pip install -e .
export FIPSIGN_API_KEY=pqa_your_real_key
npx @modelcontextprotocol/inspector python -m fipsign_mcp.server
```

Open the URL shown in the terminal (typically `http://localhost:5173`). Select a tool, fill in the parameters, and run it.

### Level 2 — Claude Desktop with local code (without publishing to PyPI)

Install in editable mode, then point Claude Desktop at the module:

```bash
pip install -e .
```

Add to your `claude_desktop_config.json` (see path below):

```json
{
  "mcpServers": {
    "fipsign": {
      "command": "python",
      "args": ["-m", "fipsign_mcp.server"],
      "env": {
        "FIPSIGN_API_KEY": "pqa_your_real_key"
      }
    }
  }
}
```

### Level 3 — Claude Desktop with published package (production)

```json
{
  "mcpServers": {
    "fipsign": {
      "command": "uvx",
      "args": ["fipsign-mcp"],
      "env": {
        "FIPSIGN_API_KEY": "pqa_your_real_key"
      }
    }
  }
}
```

Or with pip-installed package:

```json
{
  "mcpServers": {
    "fipsign": {
      "command": "fipsign-mcp",
      "env": {
        "FIPSIGN_API_KEY": "pqa_your_real_key"
      }
    }
  }
}
```

---

## Installation for Claude Desktop

`claude_desktop_config.json` is located at:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

Add the `fipsign` entry inside `mcpServers` (create the file if it doesn't exist):

```json
{
  "mcpServers": {
    "fipsign": {
      "command": "uvx",
      "args": ["fipsign-mcp"],
      "env": {
        "FIPSIGN_API_KEY": "pqa_your_real_key"
      }
    }
  }
}
```

Restart Claude Desktop after editing the config.

---

## Installation for Claude Code

```bash
claude mcp add fipsign -- env FIPSIGN_API_KEY=pqa_your_real_key uvx fipsign-mcp
```

Or manually in your project's `.claude/mcp.json`:

```json
{
  "mcpServers": {
    "fipsign": {
      "command": "uvx",
      "args": ["fipsign-mcp"],
      "env": {
        "FIPSIGN_API_KEY": "pqa_your_real_key"
      }
    }
  }
}
```

---

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `FIPSIGN_API_KEY` | Yes (for most tools) | — | Your FIPSign API key. Format: `pqa_` + 64 lowercase hex chars. Get one at app.fipsign.dev. |
| `FIPSIGN_BASE_URL` | No | `https://api.fipsign.dev` | Override API base URL (useful for self-hosted instances or local dev). |

`fipsign_health`, `fipsign_public_key`, and `fipsign_generate_key_pair` work without an API key.

---

## Key pair generation — Python vs JS SDK note

`fipsign_generate_key_pair` returns the `secretKey` as the **32-byte ML-DSA-65 seed** (base64), not the 4032-byte expanded key returned by the JS SDK's `generateKeyPair()`. The `publicKey` (1952 bytes) is identical in both SDKs and fully compatible with `fipsign_ca_issue`.

This difference only matters if you need to sign data locally on a Python device using the returned `secretKey`:

```python
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
import base64

private_key = MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(secret_key))
signature   = private_key.sign(message)
```

---

## Usage examples

Once configured, you can ask Claude:

**Signing:**
- *"Sign a token for user_123 with role admin that expires in 1 hour"*
- *"Verify this token: { payload: '...', signature: '...', algorithm: 'ML-DSA-65', issuedAt: 123 }"*
- *"Revoke this token because the user logged out"*

**Certificates:**
- *"Generate a key pair for a new IoT device"*
- *"Issue a certificate for device-serial-00123 using the public key I just generated, valid for 1 year"*
- *"Check the revocation status of cert_abc123"*
- *"Get the full CRL for our CA"*
- *"Revoke certificate cert_abc123 — device was reported stolen"*

**Monitoring:**
- *"How many tokens do I have left this month?"*
- *"Register a webhook at https://myapp.com/hooks/fipsign for limit.warning and limit.reached events"*
- *"Send a test event to my webhook"*

---

## Publishing to PyPI

```bash
pip install build twine
python -m build
twine upload dist/*
```

---

## Links

- Dashboard: [app.fipsign.dev](https://app.fipsign.dev)
- API status: [status.fipsign.dev](https://status.fipsign.dev)
- JS SDK: [npmjs.com/package/fipsign-sdk](https://www.npmjs.com/package/fipsign-sdk)
- Python SDK: [pypi.org/project/fipsign-sdk](https://pypi.org/project/fipsign-sdk/)
- TypeScript MCP: [npmjs.com/package/@fipsign/mcp](https://www.npmjs.com/package/@fipsign/mcp)
- NIST FIPS 204: [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)
