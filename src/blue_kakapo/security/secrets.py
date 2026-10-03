"""Secret store abstraction: env / encrypted file / OpenBao.

Connector credentials and provider keys are read through this, never baked into images or logs. The
default ``env`` backend reads ``BK_SECRET_<NAME>``; ``file`` reads an AES-GCM-encrypted JSON blob;
``openbao`` reads from an OpenBao/Vault KV mount over HTTP. Rotation is a matter of updating the backend
— nothing is cached beyond a request.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Protocol, runtime_checkable

import httpx


@runtime_checkable
class SecretStore(Protocol):
    def get(self, name: str) -> str | None: ...


class EnvSecretStore:
    name = "env"

    def get(self, secret: str) -> str | None:
        return os.environ.get(f"BK_SECRET_{secret.upper()}")


class FileSecretStore:
    """Reads a JSON file of secrets. If a key is configured, the file is AES-GCM encrypted."""

    name = "file"

    def __init__(self, path: Path, key: bytes | None = None) -> None:
        self.path = path
        self.key = key

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        raw = self.path.read_bytes()
        if self.key is not None:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            nonce, ct = raw[:12], raw[12:]
            raw = AESGCM(self.key).decrypt(nonce, ct, b"bk-secrets")
        return json.loads(raw.decode("utf-8"))

    def get(self, name: str) -> str | None:
        return self._load().get(name)


class OpenBaoSecretStore:
    """OpenBao / HashiCorp Vault KV v2 over HTTP."""

    name = "openbao"

    def __init__(self, addr: str, token: str, mount: str = "secret", timeout: float = 10.0) -> None:
        self.addr = addr.rstrip("/")
        self.token = token
        self.mount = mount
        self.timeout = timeout

    def get(self, name: str) -> str | None:
        url = f"{self.addr}/v1/{self.mount}/data/{name}"
        try:
            resp = httpx.get(url, headers={"X-Vault-Token": self.token}, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None
        return (((data.get("data") or {}).get("data")) or {}).get("value")


def build_secret_store(settings: object) -> SecretStore:
    backend = getattr(settings, "secret_backend", "env")
    if backend == "file" and getattr(settings, "secret_file", None):
        key: bytes | None = None
        raw_key = getattr(settings, "secret_file_key", None)
        if raw_key:
            import base64

            key = base64.b64decode(raw_key)
        return FileSecretStore(Path(settings.secret_file), key=key)  # type: ignore[attr-defined]
    if backend == "openbao" and getattr(settings, "openbao_addr", None):
        return OpenBaoSecretStore(
            settings.openbao_addr,  # type: ignore[attr-defined]
            settings.openbao_token or "",  # type: ignore[attr-defined]
            settings.openbao_mount,  # type: ignore[attr-defined]
        )
    return EnvSecretStore()
