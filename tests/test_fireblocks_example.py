from __future__ import annotations

import hashlib
import runpy
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "fireblocks"
    / "make_schnorr_corpus.py"
)
FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GENERATOR = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _decode_point(data: bytes) -> tuple[int, int]:
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("invalid compressed point")
    x = int.from_bytes(data[1:], "big")
    if x >= FIELD:
        raise ValueError("point outside field")
    y = pow((pow(x, 3, FIELD) + 7) % FIELD, (FIELD + 1) // 4, FIELD)
    if (y * y - x * x * x - 7) % FIELD:
        raise ValueError("point is not on curve")
    if y % 2 != data[0] % 2:
        y = FIELD - y
    return x, y


def _add(
    left: tuple[int, int] | None, right: tuple[int, int] | None
) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % FIELD == 0:
        return None
    if left == right:
        slope = 3 * x1 * x1 * pow(2 * y1, -1, FIELD)
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, FIELD)
    slope %= FIELD
    x3 = (slope * slope - x1 - x2) % FIELD
    return x3, (slope * (x1 - x3) - y1) % FIELD


def _mul(scalar: int, point: tuple[int, int]) -> tuple[int, int] | None:
    total = None
    while scalar:
        if scalar & 1:
            total = _add(total, point)
        point = _add(point, point)
        scalar >>= 1
    return total


def test_schnorr_corpus_has_valid_deep_path_seeds() -> None:
    namespace = runpy.run_path(str(SCRIPT))
    cases = namespace["seed_cases"]()
    order = namespace["ORDER"]
    assert _decode_point(namespace["GENERATOR"]) == GENERATOR
    assert _decode_point(namespace["TWICE_GENERATOR"]) == _add(
        GENERATOR, GENERATOR
    )
    assert all(len(seed) == 130 for seed in cases.values())
    assert cases == namespace["seed_cases"]()

    for name, seed in cases.items():
        prover_id = seed[:32]
        if name.startswith("valid-"):
            public = _decode_point(seed[32:65])
            commitment = _decode_point(seed[65:98])
            response = int.from_bytes(seed[98:], "big")
            challenge = int.from_bytes(
                hashlib.sha256(prover_id + seed[65:98] + seed[32:65]).digest(), "big"
            )
            assert 0 <= response < order
            assert _add(
                _mul(challenge, public), _mul(response, GENERATOR)
            ) == commitment, name

import unittest


class FireblocksExampleTests(unittest.TestCase):
    def test_schnorr_corpus_has_valid_deep_path_seeds(self) -> None:
        test_schnorr_corpus_has_valid_deep_path_seeds()
