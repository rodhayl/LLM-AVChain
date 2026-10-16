from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from avchain.utils.helpers import canonical_json_bytes


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def private_key_to_pem(private_key: ed25519.Ed25519PrivateKey) -> str:
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return str(pem_bytes, "utf-8")


def public_key_to_pem(public_key: ed25519.Ed25519PublicKey) -> str:
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return str(pem_bytes, "utf-8")


def load_private_key(pem_value: str) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem_value.encode("utf-8"), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("Expected an Ed25519 private key")
    return key


def load_public_key(pem_value: str) -> ed25519.Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem_value.encode("utf-8"))
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError("Expected an Ed25519 public key")
    return key


def canonicalize(data: dict[str, Any]) -> bytes:
    return canonical_json_bytes(data)


def sign_message(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> str:
    return base64.b64encode(private_key.sign(data)).decode("utf-8")


def verify_signature(
    public_key: ed25519.Ed25519PublicKey,
    data: bytes,
    signature_b64: str,
) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, data)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
