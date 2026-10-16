from __future__ import annotations

import sys
from pathlib import Path

import yaml

from avchain.crypto.keys import generate_keypair, private_key_to_pem, public_key_to_pem
from avchain.utils.helpers import ensure_directory


def generate_validator_material(
    output_dir: str | Path,
    num_validators: int = 3,
) -> Path:
    base_dir = Path(output_dir)
    keys_dir = ensure_directory(base_dir / "keys")
    registry: dict[str, list[dict[str, object]]] = {"validators": []}

    for index in range(1, num_validators + 1):
        validator_id = f"validator{index}"
        private_key, public_key = generate_keypair()
        (keys_dir / f"{validator_id}_key.pem").write_text(
            private_key_to_pem(private_key),
            encoding="utf-8",
        )
        (keys_dir / f"{validator_id}_pub.pem").write_text(
            public_key_to_pem(public_key),
            encoding="utf-8",
        )
        registry["validators"].append(
            {
                "validator_id": validator_id,
                "public_key": public_key_to_pem(public_key),
                "weight": 1.0,
            }
        )

    registry_path = base_dir / "validators.yaml"
    registry_path.write_text(
        yaml.safe_dump(registry, sort_keys=False),
        encoding="utf-8",
    )
    return registry_path


def generate_endpoint_material(
    output_dir: str | Path,
    endpoint_id: str = "endpoint-agent",
) -> Path:
    base_dir = Path(output_dir)
    keys_dir = ensure_directory(base_dir / "keys")
    private_key, public_key = generate_keypair()
    (keys_dir / f"{endpoint_id}_key.pem").write_text(
        private_key_to_pem(private_key),
        encoding="utf-8",
    )
    (keys_dir / f"{endpoint_id}_pub.pem").write_text(
        public_key_to_pem(public_key),
        encoding="utf-8",
    )
    registry = {
        "endpoints": [
            {
                "endpoint_id": endpoint_id,
                "public_key": public_key_to_pem(public_key),
                "enabled": True,
                "trust_tier": "standard",
            }
        ]
    }
    registry_path = base_dir / "endpoints.yaml"
    registry_path.write_text(
        yaml.safe_dump(registry, sort_keys=False),
        encoding="utf-8",
    )
    return registry_path


def main() -> None:
    num_validators = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(".")
    registry_path = generate_validator_material(
        output_dir=output_dir,
        num_validators=num_validators,
    )
    print(f"Generated validator registry at {registry_path}")


if __name__ == "__main__":
    main()
