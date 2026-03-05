"""Ed25519 signing utilities compatible with oktsec's canonical format."""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


@dataclass
class Keypair:
    """An Ed25519 keypair for agent identity."""

    name: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def sign_message(
        self, from_agent: str, to: str, content: str, timestamp: str
    ) -> str:
        """Sign a message using oktsec's canonical payload format.

        Canonical payload: ``from\\nto\\ncontent\\ntimestamp``
        """
        payload = f"{from_agent}\n{to}\n{content}\n{timestamp}".encode()
        sig = self.private_key.sign(payload)
        return base64.b64encode(sig).decode()

    def save(self, directory: str | Path) -> None:
        """Save keypair to PEM files (<dir>/<name>.key and <dir>/<name>.pub)."""
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)

        priv_pem = self.private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        pub_pem = self.public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        priv_path = d / f"{self.name}.key"
        pub_path = d / f"{self.name}.pub"

        priv_path.write_bytes(priv_pem)
        os.chmod(priv_path, 0o600)
        pub_path.write_bytes(pub_pem)


def load_keypair(directory: str | Path, name: str) -> Keypair:
    """Load an oktsec keypair from PEM files.

    Supports both PKCS8 and raw seed PEM formats (oktsec uses raw seed
    with type ``OKTSEC ED25519 PRIVATE KEY``).
    """
    d = Path(directory)
    priv_path = d / f"{name}.key"
    priv_pem = priv_path.read_bytes()

    # oktsec's Go keygen writes raw 64-byte Ed25519 seeds in a custom PEM type.
    # The `cryptography` library expects PKCS8, so we handle both.
    if b"OKTSEC ED25519 PRIVATE KEY" in priv_pem:
        private_key = _load_raw_oktsec_key(priv_pem)
    else:
        private_key = load_pem_private_key(priv_pem, password=None)  # type: ignore[assignment]
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError(f"key in {priv_path} is not Ed25519")

    public_key = private_key.public_key()

    # Try loading .pub if it exists (for verification)
    pub_path = d / f"{name}.pub"
    if pub_path.exists():
        pub_pem = pub_path.read_bytes()
        if b"OKTSEC ED25519 PUBLIC KEY" in pub_pem:
            _load_raw_oktsec_pub(pub_pem)  # validate only
        else:
            loaded_pub = load_pem_public_key(pub_pem)
            if not isinstance(loaded_pub, Ed25519PublicKey):
                raise ValueError(f"public key in {pub_path} is not Ed25519")

    return Keypair(name=name, private_key=private_key, public_key=public_key)


def generate_keypair(name: str) -> Keypair:
    """Generate a new Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    return Keypair(
        name=name,
        private_key=private_key,
        public_key=private_key.public_key(),
    )


def _load_raw_oktsec_key(pem_data: bytes) -> Ed25519PrivateKey:
    """Load oktsec's raw seed PEM format."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    lines = pem_data.decode().strip().splitlines()
    b64 = "".join(
        line
        for line in lines
        if not line.startswith("-----")
    )
    raw = base64.b64decode(b64)

    # oktsec writes 64-byte Ed25519 private keys (seed + public)
    if len(raw) == 64:
        return Ed25519PrivateKey.from_private_bytes(raw[:32])
    elif len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)
    else:
        raise ValueError(f"unexpected oktsec key length: {len(raw)} bytes")


def _load_raw_oktsec_pub(pem_data: bytes) -> Ed25519PublicKey:
    """Load oktsec's raw public key PEM format."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    lines = pem_data.decode().strip().splitlines()
    b64 = "".join(
        line
        for line in lines
        if not line.startswith("-----")
    )
    raw = base64.b64decode(b64)

    if len(raw) != 32:
        raise ValueError(f"unexpected oktsec public key length: {len(raw)} bytes")
    return Ed25519PublicKey.from_public_bytes(raw)
