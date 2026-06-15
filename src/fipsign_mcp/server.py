"""
fipsign_mcp.server — MCP server for FIPSign post-quantum signing API.

Exposes 11 tools covering the full FIPSign runtime API:
signing, verification, revocation, usage, CA certificate lifecycle,
and key pair generation.

Configuration (environment variables):
    FIPSIGN_API_KEY   — required for most tools (pqa_ + 64 hex chars)
    FIPSIGN_BASE_URL  — optional, defaults to https://api.fipsign.dev

Transport: stdio (compatible with Claude Desktop and Claude Code)
"""

from __future__ import annotations

import base64
import json
import os
import sys
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    TextContent,
    Tool,
)

# ─── Configuration ────────────────────────────────────────────────────────────

API_KEY  = os.environ.get("FIPSIGN_API_KEY", "")
BASE_URL = os.environ.get("FIPSIGN_BASE_URL", "https://api.fipsign.dev").rstrip("/")

# ─── HTTP helper ──────────────────────────────────────────────────────────────

async def api_request(
    method: str,
    path: str,
    body: Any = None,
) -> tuple[bool, Any]:
    """
    Make an authenticated request to the FIPSign API.
    Returns (ok: bool, data: Any).
    """
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.request(
                method,
                f"{BASE_URL}{path}",
                headers=headers,
                content=json.dumps(body).encode() if body is not None else None,
            )
            try:
                data = response.json()
            except Exception:
                data = {"success": False, "error": f"HTTP {response.status_code} — non-JSON response"}
            return response.is_success, data
        except httpx.TimeoutException:
            return False, {"success": False, "error": "Request timed out after 30 seconds"}
        except httpx.NetworkError as exc:
            return False, {"success": False, "error": f"Network error: {exc}"}

# ─── Key pair generation ──────────────────────────────────────────────────────

def _generate_key_pair() -> dict[str, Any]:
    """
    Generate an ML-DSA-65 key pair using pyca/cryptography >= 48.0.0.
    Returns publicKey (base64, 1952 bytes) and secretKey (base64, 32-byte seed).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    except ImportError:
        raise RuntimeError(
            "generate_key_pair requires cryptography >= 48.0.0. "
            "Install with: pip install 'cryptography>=48.0.0'"
        )

    private_key = MLDSA65PrivateKey.generate()
    public_key  = private_key.public_key()

    pub_b64  = base64.b64encode(public_key.public_bytes_raw()).decode()
    seed_b64 = base64.b64encode(private_key.private_bytes_raw()).decode()

    return {
        "publicKey": pub_b64,
        "secretKey": seed_b64,
        "algorithm": "ML-DSA-65",
        "standard":  "NIST FIPS 204",
        "sizes": {
            "publicKeyBytes": len(public_key.public_bytes_raw()),
            "secretKeyBytes": len(private_key.private_bytes_raw()),
            "note": "secretKey is the 32-byte seed form (Python SDK convention). The publicKey is 1952 bytes — compatible with fipsign_ca_issue and the JS SDK.",
        },
        "note": "Store secretKey securely on the device. Never send it to any server. Pass publicKey to fipsign_ca_issue.",
    }

# ─── Response helpers ─────────────────────────────────────────────────────────

def _ok(data: Any) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(data, indent=2))]
    )

def _err(message: str, detail: Any = None) -> CallToolResult:
    payload: dict[str, Any] = {"error": message}
    if detail is not None:
        payload["detail"] = detail
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, indent=2))],
        isError=True,
    )

def _missing_api_key() -> CallToolResult:
    return _err(
        "FIPSIGN_API_KEY is not set. "
        "Export it before starting the server: export FIPSIGN_API_KEY=pqa_..."
    )

# ─── Tool definitions ─────────────────────────────────────────────────────────

TOOLS: list[Tool] = [
    # ── Infrastructure ─────────────────────────────────────────────────────────

    Tool(
        name="fipsign_health",
        description=(
            "Check the health of the FIPSign service. Returns the service status, "
            "algorithm (ML-DSA-65), NIST standard, and version. No API key required. "
            "Use this to verify the service is reachable before running other operations."
        ),
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),

    Tool(
        name="fipsign_public_key",
        description=(
            "Get the current ML-DSA-65 public key of the FIPSign server. Returns a "
            "base64-encoded 1952-byte public key. Use this when you need to verify token "
            "signatures independently without calling the /verify endpoint (e.g. for "
            "offline verification or third-party auditing). No API key required."
        ),
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),

    # ── Core signing ────────────────────────────────────────────────────────────

    Tool(
        name="fipsign_sign",
        description=(
            "Sign any payload with ML-DSA-65 (NIST FIPS 204). The only required field is "
            "'sub' — any string identifying the entity being signed: a user ID, order ID, "
            "document hash, device serial, AI agent action, or anything else. All other "
            "fields are stored in the payload and returned on verify. Costs 1 token. "
            "Returns the signed token object (payload, signature, algorithm, issuedAt) "
            "plus usage info."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "sub": {
                    "type": "string",
                    "description": (
                        "Required. Entity identifier. Max 128 characters. "
                        "Examples: 'user_123', 'order_456', 'doc_hash_abc', "
                        "'device_serial_001', 'agent_action_summarize'."
                    ),
                },
                "expiresInSeconds": {
                    "type": "number",
                    "description": (
                        "Token lifetime in seconds. Default: 3600 (1 hour). "
                        "Pass a larger value for long-lived tokens (e.g. document signatures: "
                        "365 * 24 * 3600)."
                    ),
                },
            },
            "required": ["sub"],
            "additionalProperties": {
                "description": (
                    "Any additional custom fields to embed in the payload. "
                    "Max 10 extra fields, string values max 256 chars."
                ),
            },
        },
    ),

    Tool(
        name="fipsign_verify",
        description=(
            "Verify a FIPSign token signed with ML-DSA-65. Checks the cryptographic "
            "signature, expiry, and revocation list. Returns valid:true with the decoded "
            "payload on success, or valid:false with an error message on failure. "
            "Never throws — always returns a result. Costs 1 token."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "token": {
                    "type": "object",
                    "description": (
                        "The token object returned by fipsign_sign. "
                        "Must have: payload (string), signature (string), "
                        "algorithm (string), issuedAt (number)."
                    ),
                    "properties": {
                        "payload":   {"type": "string"},
                        "signature": {"type": "string"},
                        "algorithm": {"type": "string"},
                        "issuedAt":  {"type": "number"},
                    },
                    "required": ["payload", "signature", "algorithm", "issuedAt"],
                },
            },
            "required": ["token"],
        },
    ),

    Tool(
        name="fipsign_revoke",
        description=(
            "Permanently revoke a token. Once revoked, all future verify() calls will "
            "reject the token even if its signature is valid and it has not expired. "
            "Idempotent: revoking an already-revoked token returns success without "
            "consuming an extra token. Costs 1 token. "
            "Note: calling this on an already-expired token returns an error (400)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "token": {
                    "type": "object",
                    "description": "The token object to revoke. Must have: payload, signature, algorithm, issuedAt.",
                    "properties": {
                        "payload":   {"type": "string"},
                        "signature": {"type": "string"},
                        "algorithm": {"type": "string"},
                        "issuedAt":  {"type": "number"},
                    },
                    "required": ["payload", "signature", "algorithm", "issuedAt"],
                },
                "reason": {
                    "type": "string",
                    "description": (
                        "Optional human-readable reason stored server-side. "
                        "Examples: 'user logged out', 'order cancelled', "
                        "'suspicious activity detected'."
                    ),
                },
            },
            "required": ["token"],
        },
    ),

    # ── Account ─────────────────────────────────────────────────────────────────

    Tool(
        name="fipsign_usage",
        description=(
            "Get the current token balance and 6-month usage history for this API key's "
            "account. Returns free tokens remaining (resets monthly), pack tokens remaining "
            "(never expire), total remaining, and a monthly breakdown. "
            "Free — no token cost. Use before batch operations to confirm sufficient balance."
        ),
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),

    # ── Key generation ──────────────────────────────────────────────────────────

    Tool(
        name="fipsign_generate_key_pair",
        description=(
            "Generate an ML-DSA-65 key pair locally (no API call, no token cost). "
            "Returns a base64-encoded public key (1952 bytes) and secret key (32-byte seed). "
            "Use the publicKey when calling fipsign_ca_issue to certify a device or entity. "
            "SECURITY WARNING: the secretKey is sensitive — store it securely on the device "
            "and never send it to any server. The secretKey will appear in this tool's "
            "response; treat it like a private key.\n\n"
            "Note: The Python SDK returns the secretKey as a 32-byte seed (base64). "
            "This differs from the JS SDK which returns a 4032-byte expanded key. "
            "Both publicKeys (1952 bytes) are fully interoperable with the FIPSign backend."
        ),
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),

    # ── Certificate Authority ───────────────────────────────────────────────────

    Tool(
        name="fipsign_ca_issue",
        description=(
            "Issue a post-quantum certificate signed by the project's CA. The certificate "
            "certifies that the entity identified by 'subject' controls the given ML-DSA-65 "
            "public key. Supports both PQCert (native JSON) and X.509 (standard PEM) CA "
            "formats — the format is determined by which CA type was created in the "
            "dashboard. For PQCert CAs, the response includes a certificate JSON object. "
            "For X.509 CAs, it includes a PEM string. Costs 1 token.\n\n"
            "Required: subject (entity name/ID), publicKey (base64 ML-DSA-65 public key — "
            "generate with fipsign_generate_key_pair), expiresInSeconds "
            "(min 60, max 157680000 = 5 years).\n\n"
            "Optional: meta (up to 10 key-value pairs — PQCert CAs only; passing meta "
            "to an X.509 CA returns a 400 error).\n\n"
            "The returned certId (in meta.certId) is what you need for "
            "fipsign_ca_revoke_cert and fipsign_ca_get_cert."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "subject": {
                    "type": "string",
                    "description": (
                        "Entity identifier to certify. Examples: 'device-serial-00123', "
                        "'service-payment-processor', 'lock-v3-batch-2026'. Max 256 characters."
                    ),
                },
                "publicKey": {
                    "type": "string",
                    "description": (
                        "Base64-encoded ML-DSA-65 public key of the entity to certify "
                        "(1952 bytes decoded). Generate with fipsign_generate_key_pair."
                    ),
                },
                "expiresInSeconds": {
                    "type": "number",
                    "description": (
                        "Certificate lifetime in seconds. Min: 60 (1 minute). "
                        "Max: 157680000 (5 years). Example: 31536000 = 1 year."
                    ),
                },
                "meta": {
                    "type": "object",
                    "description": (
                        "Optional custom key-value pairs to embed in the certificate "
                        "(PQCert CAs only — returns 400 for X.509 CAs). Max 10 keys. "
                        'Example: {"model": "lock-v3", "batch": "2026-05"}.'
                    ),
                    "additionalProperties": True,
                },
            },
            "required": ["subject", "publicKey", "expiresInSeconds"],
        },
    ),

    Tool(
        name="fipsign_ca_revoke_cert",
        description=(
            "Revoke a certificate immediately. From this point on, the certificate will "
            "appear in the CRL returned by fipsign_ca_get_crl. Use fipsign_ca_get_cert to "
            "check real-time revocation status of a single certificate. Costs 1 token. "
            "Returns 409 if the certificate is already revoked."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "certId": {
                    "type": "string",
                    "description": (
                        "The certificate ID to revoke (cert_...). "
                        "For PQCert: the 'id' field of the certificate object. "
                        "For X.509: the 'certId' field from meta returned by fipsign_ca_issue."
                    ),
                },
                "reason": {
                    "type": "string",
                    "description": (
                        "Optional reason for revocation. Max 256 characters. "
                        "Examples: 'device decommissioned', 'device reported stolen', "
                        "'key compromise'."
                    ),
                },
            },
            "required": ["certId"],
        },
    ),

    Tool(
        name="fipsign_ca_get_cert",
        description=(
            "Get a certificate by ID and its current real-time status "
            "(revoked, expired, revokedAt, expiresAt). Use this for single certificate "
            "checks before authorizing high-value operations. For bulk offline revocation "
            "checks across many certificates, use fipsign_ca_get_crl instead. "
            "Free — no token cost."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "certId": {
                    "type": "string",
                    "description": (
                        "The certificate ID (cert_...). "
                        "For PQCert: certificate.id. "
                        "For X.509: meta.certId from fipsign_ca_issue."
                    ),
                },
            },
            "required": ["certId"],
        },
    ),

    Tool(
        name="fipsign_ca_get_crl",
        description=(
            "Get the Certificate Revocation List (CRL) for this project's CA. Returns all "
            "revoked certificate IDs with their revocation timestamps and reasons. Use this "
            "to check revocation status of multiple certificates offline — download once, "
            "check locally. For a single certificate's real-time status use "
            "fipsign_ca_get_cert instead. Free — no token cost. For X.509 CAs the CRL is "
            "signed with ML-DSA-65 and includes the full signed object in the 'raw' field."
        ),
        inputSchema={
            "type": "object",
            "properties": {},
            "required": [],
        },
    ),
]

# ─── Tool handlers ────────────────────────────────────────────────────────────

async def handle_tool(name: str, args: dict[str, Any]) -> CallToolResult:
    # Tools that don't require API key
    if name == "fipsign_health":
        ok, data = await api_request("GET", "/health")
        return _ok(data)

    if name == "fipsign_public_key":
        ok, data = await api_request("GET", "/public-key")
        return _ok(data)

    if name == "fipsign_generate_key_pair":
        try:
            result = _generate_key_pair()
            return _ok(result)
        except RuntimeError as exc:
            return _err(str(exc))

    # All remaining tools require API key
    if not API_KEY:
        return _missing_api_key()

    if name == "fipsign_sign":
        sub = args.get("sub")
        if not sub or not isinstance(sub, str):
            return _err('"sub" is required and must be a string')
        body: dict[str, Any] = {k: v for k, v in args.items() if k != "expiresInSeconds"}
        if "expiresInSeconds" in args:
            body["expiresInSeconds"] = args["expiresInSeconds"]
        ok_flag, data = await api_request("POST", "/sign", body)
        if not ok_flag:
            return _err("Sign failed", data)
        return _ok(data)

    if name == "fipsign_verify":
        token = args.get("token")
        if not token or not isinstance(token, dict):
            return _err('"token" is required and must be the token object returned by fipsign_sign')
        ok_flag, data = await api_request("POST", "/verify", {"token": token})
        return _ok(data)

    if name == "fipsign_revoke":
        token = args.get("token")
        if not token or not isinstance(token, dict):
            return _err('"token" is required and must be the token object returned by fipsign_sign')
        body = {"token": token}
        if "reason" in args:
            body["reason"] = args["reason"]
        ok_flag, data = await api_request("POST", "/revoke", body)
        if not ok_flag:
            return _err("Revoke failed", data)
        return _ok(data)

    if name == "fipsign_usage":
        ok_flag, data = await api_request("GET", "/usage")
        if not ok_flag:
            return _err("Usage request failed", data)
        return _ok(data)

    if name == "fipsign_ca_issue":
        subject = args.get("subject")
        public_key = args.get("publicKey")
        expires_in_seconds = args.get("expiresInSeconds")

        if not subject or not isinstance(subject, str):
            return _err('"subject" is required')
        if not public_key or not isinstance(public_key, str):
            return _err('"publicKey" is required — generate one with fipsign_generate_key_pair')
        if not isinstance(expires_in_seconds, (int, float)):
            return _err('"expiresInSeconds" is required and must be a number (min 60, max 157680000)')

        body = {
            "subject":          subject,
            "publicKey":        public_key,
            "expiresInSeconds": expires_in_seconds,
        }
        if "meta" in args:
            body["meta"] = args["meta"]

        ok_flag, data = await api_request("POST", "/ca/issue", body)
        if not ok_flag:
            return _err("CA issue failed", data)
        return _ok(data)

    if name == "fipsign_ca_revoke_cert":
        cert_id = args.get("certId")
        if not cert_id or not isinstance(cert_id, str):
            return _err('"certId" is required')
        body = {"certId": cert_id}
        if "reason" in args:
            body["reason"] = args["reason"]
        ok_flag, data = await api_request("POST", "/ca/revoke", body)
        if not ok_flag:
            return _err("CA revoke failed", data)
        return _ok(data)

    if name == "fipsign_ca_get_cert":
        cert_id = args.get("certId")
        if not cert_id or not isinstance(cert_id, str):
            return _err('"certId" is required')
        ok_flag, data = await api_request("GET", f"/ca/certificate/{cert_id}")
        if not ok_flag:
            return _err("CA get cert failed", data)
        return _ok(data)

    if name == "fipsign_ca_get_crl":
        ok_flag, data = await api_request("GET", "/ca/crl")
        if not ok_flag:
            return _err("CA get CRL failed", data)
        return _ok(data)

    return _err(f"Unknown tool: {name}")

# ─── Server setup ─────────────────────────────────────────────────────────────

app = Server("fipsign-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        result = await handle_tool(name, arguments or {})
        return result.content  # type: ignore[return-value]
    except Exception as exc:
        error_result = _err(f"Unexpected error in tool '{name}': {exc}")
        return error_result.content  # type: ignore[return-value]


# ─── Entry point ─────────────────────────────────────────────────────────────

def main() -> None:
    import asyncio

    async def _run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options(),
            )

    asyncio.run(_run())


if __name__ == "__main__":
    main()
