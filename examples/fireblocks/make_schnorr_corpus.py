#!/usr/bin/env python3
"""Generate deterministic secp256k1 Schnorr verifier seeds for the example harness."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
GENERATOR = bytes.fromhex(
    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
)
TWICE_GENERATOR = bytes.fromhex(
    "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"
)
BASE_ID = bytes(range(32))
INPUT_LENGTH = 32 + 33 + 33 + 32


def valid_seed(
    prover_id: bytes,
    public_point: bytes,
    commitment: bytes,
    secret: int,
    nonce: int,
) -> bytes:
    """Encode an algebraically valid proof: R = c*P + s*G, s = nonce - c*secret."""
    if len(prover_id) != 32 or len(public_point) != 33 or len(commitment) != 33:
        raise ValueError("expected a 32-byte ID and 33-byte compressed points")
    if not (1 <= secret < ORDER and 1 <= nonce < ORDER):
        raise ValueError("secret and nonce must be nonzero curve scalars")
    challenge = int.from_bytes(
        hashlib.sha256(prover_id + commitment + public_point).digest(), "big"
    )
    response = (nonce - challenge * secret) % ORDER
    return prover_id + public_point + commitment + response.to_bytes(32, "big")


def seed_cases() -> dict[str, bytes]:
    baseline = valid_seed(BASE_ID, GENERATOR, GENERATOR, 1, 1)
    proof = baseline[65:]
    cases = {
        "valid-baseline": baseline,
        "valid-zero-id": valid_seed(bytes(32), GENERATOR, GENERATOR, 1, 1),
        "valid-ff-id": valid_seed(bytes([0xFF]) * 32, GENERATOR, GENERATOR, 1, 1),
        "valid-nonce-two": valid_seed(BASE_ID, GENERATOR, TWICE_GENERATOR, 1, 2),
        "valid-secret-two": valid_seed(BASE_ID, TWICE_GENERATOR, GENERATOR, 2, 1),
        "valid-both-two": valid_seed(
            BASE_ID, TWICE_GENERATOR, TWICE_GENERATOR, 2, 2
        ),
        "mismatch-id": bytes([BASE_ID[0] ^ 1]) + baseline[1:],
        "mismatch-public": BASE_ID + TWICE_GENERATOR + proof,
        "mismatch-commitment": BASE_ID + GENERATOR + TWICE_GENERATOR + proof[33:],
        "invalid-public-zero": BASE_ID + bytes(33) + proof,
        "invalid-public-prefix": BASE_ID + b"\x04" + GENERATOR[1:] + proof,
        "invalid-commitment-zero": BASE_ID + GENERATOR + bytes(33) + proof[33:],
        "scalar-zero": baseline[:98] + bytes(32),
        "scalar-order": baseline[:98] + ORDER.to_bytes(32, "big"),
        "scalar-max": baseline[:98] + bytes([0xFF]) * 32,
    }
    assert all(len(item) == INPUT_LENGTH for item in cases.values())
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path, help="libFuzzer corpus directory")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    cases = seed_cases()
    for name, data in sorted(cases.items()):
        (args.output_dir / name).write_bytes(data)
    print(f"wrote {len(cases)} deterministic seeds to {args.output_dir}")


if __name__ == "__main__":
    main()
