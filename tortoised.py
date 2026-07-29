#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


APP_NAME = "tortoised"
APP_VERSION = "0.1.0"
SIGN_NAMESPACE = "tortoised"

DEFAULT_CONFIG_PATH = "/etc/tortoise-ai/tortoised.json"
DEFAULT_KEY_PATH = "/etc/tortoise-ai/keys/tortoised_ed25519"
DEFAULT_PUBKEY_PATH = "/etc/tortoise-ai/keys/tortoised_ed25519.pub"
DEFAULT_ALLOWED_SIGNERS = "/etc/tortoise-ai/allowed_signers"

CHALLENGE_TTL_SECONDS = 120


app = FastAPI(
    title="Tortoise AI Service Infrastructure",
    version=APP_VERSION,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_text(path: str | Path) -> str | None:
    p = Path(path)
    if not p.exists():
        return None
    return p.read_text(encoding="utf-8").strip()


def hostname() -> str:
    return socket.gethostname()


def default_node_id() -> str:
    return f"tortoised@{hostname()}"


def ssh_pubkey_fingerprint(pubkey_path: str | Path) -> str | None:
    p = Path(pubkey_path)
    if not p.exists():
        return None

    try:
        result = subprocess.run(
            ["ssh-keygen", "-lf", str(p)],
            text=True,
            capture_output=True,
            check=True,
        )
    except Exception:
        return None

    return result.stdout.strip()


def run_ssh_keygen_sign(private_key_path: str, message: str) -> str:
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as msg_file:
        msg_file.write(message)
        msg_file.flush()
        msg_path = msg_file.name

    sig_path = msg_path + ".sig"

    try:
        with open(msg_path, "rb") as stdin:
            subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "sign",
                    "-f",
                    private_key_path,
                    "-n",
                    SIGN_NAMESPACE,
                    "-q",
                    "-O",
                    "hashalg=sha512",
                ],
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )

        # OpenSSH writes the signature to message.sig by default.
        signature = Path(sig_path).read_text(encoding="utf-8")
        return signature
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"ssh-keygen signing failed: {exc.stderr.decode(errors='replace') if exc.stderr else exc}"
        ) from exc
    finally:
        Path(msg_path).unlink(missing_ok=True)
        Path(sig_path).unlink(missing_ok=True)


def run_ssh_keygen_verify(
    allowed_signers_path: str,
    principal: str,
    message: str,
    signature: str,
) -> bool:
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as msg_file:
        msg_file.write(message)
        msg_file.flush()
        msg_path = msg_file.name

    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as sig_file:
        sig_file.write(signature)
        sig_file.flush()
        sig_path = sig_file.name

    try:
        with open(msg_path, "rb") as stdin:
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    allowed_signers_path,
                    "-I",
                    principal,
                    "-n",
                    SIGN_NAMESPACE,
                    "-s",
                    sig_path,
                ],
                stdin=stdin,
                text=False,
                capture_output=True,
            )

        return result.returncode == 0
    finally:
        Path(msg_path).unlink(missing_ok=True)
        Path(sig_path).unlink(missing_ok=True)


@dataclass
class RuntimeConfig:
    config_path: str = field(
        default_factory=lambda: os.getenv("TORTOISED_CONFIG", DEFAULT_CONFIG_PATH)
    )
    private_key_path: str = field(
        default_factory=lambda: os.getenv("TORTOISED_KEY", DEFAULT_KEY_PATH)
    )
    public_key_path: str = field(
        default_factory=lambda: os.getenv("TORTOISED_PUBKEY", DEFAULT_PUBKEY_PATH)
    )
    allowed_signers_path: str = field(
        default_factory=lambda: os.getenv(
            "TORTOISED_ALLOWED_SIGNERS", DEFAULT_ALLOWED_SIGNERS
        )
    )
    host: str = field(default_factory=hostname)
    node_id: str = field(
        default_factory=lambda: os.getenv("TORTOISED_NODE_ID", default_node_id())
    )
    listen_host: str = field(
        default_factory=lambda: os.getenv("TORTOISED_HOST", "127.0.0.1")
    )
    listen_port: int = field(
        # Default aligned with licd's advertised tortoised_port (LICD_TORTOISED_PORT)
        # so licd-console can forward and reach tortoised without extra config.
        default_factory=lambda: int(os.getenv("TORTOISED_PORT", "8767"))
    )

    def config(self) -> dict[str, Any]:
        return load_json_file(self.config_path)


CFG = RuntimeConfig()


def build_default_services(config: dict[str, Any]) -> list[dict[str, Any]]:
    services = config.get("services")
    if isinstance(services, list):
        return services

    clones_brain_port = int(os.getenv("CLONES_BRAIN_PORT", "8765"))
    dream_server_port = int(os.getenv("DREAM_SERVER_PORT", "8181"))
    return [
        {
            "name": "tortoised",
            "role": "node-registry",
            "host": "127.0.0.1",
            "port": CFG.listen_port,
            "url": f"http://{CFG.listen_host}:{CFG.listen_port}",
            "status": "configured",
        },
        {
            "name": "clones-brain",
            "role": "local-memory",
            "host": "127.0.0.1",
            "port": clones_brain_port,
            "url": f"http://127.0.0.1:{clones_brain_port}",
            "status": "unknown",
        },
        {
            "name": "dream-server",
            "role": "ambiguous-context",
            "host": "127.0.0.1",
            "port": dream_server_port,
            "url": f"http://127.0.0.1:{dream_server_port}",
            "status": "unknown",
        },
    ]


def build_default_policy(config: dict[str, Any]) -> dict[str, Any]:
    policy = config.get("policy")
    if isinstance(policy, dict):
        return policy

    return {
        "allow_discovery": True,
        "allow_query": True,
        "allow_capture": False,
        "allow_remote_execution": False,
        "requires_broker_for_write": True,
        "requires_broker_for_service_restart": True,
        "requires_broker_for_package_install": True,
        "notes": [
            "tortoised v0.1 is disclosure-only.",
            "No remote execution is supported.",
            "Writes and service actions must be mediated by a future broker layer.",
        ],
    }


def build_node_manifest() -> dict[str, Any]:
    config = CFG.config()
    pubkey = read_text(CFG.public_key_path)

    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "node_id": config.get("node_id", CFG.node_id),
        "hostname": config.get("hostname", CFG.host),
        "machine_role": config.get("machine_role", "tortoise-node"),
        "description": config.get(
            "description",
            "A Tortoise AI node exposing local service identity, policy, and available AI memory services.",
        ),
        "public_key": pubkey,
        "public_key_fingerprint": ssh_pubkey_fingerprint(CFG.public_key_path),
        "config_path": CFG.config_path,
        "allowed_signers_path": CFG.allowed_signers_path,
        "time": utc_now(),
    }


def build_services_manifest() -> dict[str, Any]:
    config = CFG.config()
    return {
        "ok": True,
        "node_id": config.get("node_id", CFG.node_id),
        "services": build_default_services(config),
        "time": utc_now(),
    }


def build_policy_manifest() -> dict[str, Any]:
    config = CFG.config()
    return {
        "ok": True,
        "node_id": config.get("node_id", CFG.node_id),
        "policy": build_default_policy(config),
        "time": utc_now(),
    }


class ChallengeRecord(BaseModel):
    challenge_id: str
    nonce: str
    issued_at: float
    expires_at: float


class ChallengeResponse(BaseModel):
    ok: bool
    node_id: str
    challenge_id: str
    nonce: str
    issued_at: str
    expires_at: str
    namespace: str = SIGN_NAMESPACE
    instructions: str


class VerifyRequest(BaseModel):
    challenge_id: str = Field(..., min_length=1)
    principal: str = Field(..., min_length=1)
    signature: str = Field(..., min_length=1)


class VerifyResponse(BaseModel):
    ok: bool
    verified: bool
    node_id: str
    principal: str
    manifest: dict[str, Any]
    manifest_signature: Optional[str] = None
    time: str


CHALLENGES: dict[str, ChallengeRecord] = {}


def prune_challenges() -> None:
    now = time.time()
    expired = [cid for cid, rec in CHALLENGES.items() if rec.expires_at < now]
    for cid in expired:
        CHALLENGES.pop(cid, None)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": APP_NAME,
        "version": APP_VERSION,
        "node_id": CFG.config().get("node_id", CFG.node_id),
        "hostname": CFG.host,
        "time": utc_now(),
    }


@app.get("/node")
def node() -> dict[str, Any]:
    manifest = build_node_manifest()
    return {
        "ok": True,
        "node": manifest,
    }


@app.get("/services")
def services() -> dict[str, Any]:
    return build_services_manifest()


@app.get("/policy")
def policy() -> dict[str, Any]:
    return build_policy_manifest()


@app.post("/challenge")
def challenge() -> ChallengeResponse:
    prune_challenges()

    now = time.time()
    challenge_id = secrets.token_urlsafe(24)
    raw_nonce = secrets.token_bytes(32)
    nonce = base64.urlsafe_b64encode(raw_nonce).decode("ascii").rstrip("=")
    expires_at = now + CHALLENGE_TTL_SECONDS

    CHALLENGES[challenge_id] = ChallengeRecord(
        challenge_id=challenge_id,
        nonce=nonce,
        issued_at=now,
        expires_at=expires_at,
    )

    return ChallengeResponse(
        ok=True,
        node_id=CFG.config().get("node_id", CFG.node_id),
        challenge_id=challenge_id,
        nonce=nonce,
        issued_at=datetime.fromtimestamp(now, timezone.utc).isoformat(),
        expires_at=datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
        instructions=(
            "Sign the nonce with ssh-keygen -Y sign using namespace "
            f"{SIGN_NAMESPACE}, then POST the signature to /verify."
        ),
    )


@app.post("/verify")
def verify(req: VerifyRequest) -> VerifyResponse:
    prune_challenges()

    rec = CHALLENGES.get(req.challenge_id)
    if not rec:
        raise HTTPException(status_code=400, detail="Unknown or expired challenge_id.")

    if rec.expires_at < time.time():
        CHALLENGES.pop(req.challenge_id, None)
        raise HTTPException(status_code=400, detail="Challenge expired.")

    allowed = Path(CFG.allowed_signers_path)
    if not allowed.exists():
        raise HTTPException(
            status_code=500,
            detail=f"Allowed signers file does not exist: {CFG.allowed_signers_path}",
        )

    verified = run_ssh_keygen_verify(
        allowed_signers_path=CFG.allowed_signers_path,
        principal=req.principal,
        message=rec.nonce,
        signature=req.signature,
    )

    if not verified:
        raise HTTPException(status_code=403, detail="Signature verification failed.")

    # One-time use challenge.
    CHALLENGES.pop(req.challenge_id, None)

    manifest = {
        "node": build_node_manifest(),
        "services": build_services_manifest()["services"],
        "policy": build_policy_manifest()["policy"],
    }

    manifest_json = json.dumps(manifest, sort_keys=True, separators=(",", ":"))

    manifest_signature: Optional[str] = None
    if Path(CFG.private_key_path).exists():
        try:
            manifest_signature = run_ssh_keygen_sign(
                CFG.private_key_path, manifest_json
            )
        except Exception:
            manifest_signature = None

    return VerifyResponse(
        ok=True,
        verified=True,
        node_id=CFG.config().get("node_id", CFG.node_id),
        principal=req.principal,
        manifest=manifest,
        manifest_signature=manifest_signature,
        time=utc_now(),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "tortoised:app",
        host=CFG.listen_host,
        port=CFG.listen_port,
        reload=False,
    )
