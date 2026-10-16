from __future__ import annotations

from avchain.crypto.keys import (
    canonicalize,
    generate_keypair,
    load_private_key,
    load_public_key,
    private_key_to_pem,
    public_key_to_pem,
    sign_message,
    verify_signature,
)


def test_sign_and_verify_round_trip() -> None:
    private_key, public_key = generate_keypair()
    payload = canonicalize({"entry_id": "123", "action": "promote"})
    signature = sign_message(private_key, payload)
    assert verify_signature(public_key, payload, signature)


def test_pem_round_trip() -> None:
    private_key, public_key = generate_keypair()
    loaded_private = load_private_key(private_key_to_pem(private_key))
    loaded_public = load_public_key(public_key_to_pem(public_key))
    payload = canonicalize({"value": "hello"})
    signature = sign_message(loaded_private, payload)
    assert verify_signature(loaded_public, payload, signature)
