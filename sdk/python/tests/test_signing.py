"""Tests for Ed25519 signing utilities."""

import base64
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from oktsec.signing import Keypair, generate_keypair, load_keypair


def test_generate_keypair():
    kp = generate_keypair("test-agent")
    assert kp.name == "test-agent"
    assert kp.private_key is not None
    assert isinstance(kp.public_key, Ed25519PublicKey)


def test_sign_message():
    kp = generate_keypair("alice")
    sig = kp.sign_message("alice", "bob", "hello", "2026-01-01T00:00:00Z")

    # Should be valid base64
    raw = base64.b64decode(sig)
    assert len(raw) == 64  # Ed25519 signature is always 64 bytes


def test_sign_message_verifiable():
    kp = generate_keypair("alice")
    content = "test message"
    ts = "2026-01-01T00:00:00Z"
    sig = kp.sign_message("alice", "bob", content, ts)

    # Verify with public key
    payload = f"alice\nbob\n{content}\n{ts}".encode()
    raw_sig = base64.b64decode(sig)
    # This will raise if verification fails
    kp.public_key.verify(raw_sig, payload)


def test_save_and_load_keypair():
    kp = generate_keypair("round-trip")

    with tempfile.TemporaryDirectory() as d:
        kp.save(d)

        # Verify files exist
        assert (Path(d) / "round-trip.key").exists()
        assert (Path(d) / "round-trip.pub").exists()

        # Load back
        loaded = load_keypair(d, "round-trip")
        assert loaded.name == "round-trip"

        # Sign with original, verify with loaded
        sig = kp.sign_message("a", "b", "c", "t")
        payload = b"a\nb\nc\nt"
        raw_sig = base64.b64decode(sig)
        loaded.public_key.verify(raw_sig, payload)


def test_save_keypair_permissions():
    kp = generate_keypair("perms-test")

    with tempfile.TemporaryDirectory() as d:
        kp.save(d)
        priv_path = Path(d) / "perms-test.key"
        mode = priv_path.stat().st_mode & 0o777
        assert mode == 0o600, f"private key permissions = {oct(mode)}, want 0600"


def test_different_messages_different_signatures():
    kp = generate_keypair("signer")
    ts = "2026-01-01T00:00:00Z"

    sig1 = kp.sign_message("a", "b", "message one", ts)
    sig2 = kp.sign_message("a", "b", "message two", ts)

    assert sig1 != sig2
