# Fireblocks MPC Schnorr verifier fuzz example

This example targets schnorr_zkp_verify in
[fireblocks/mpc-lib](https://github.com/fireblocks/mpc-lib) at commit
00ae08b7f1bdbb887aedece384aca2f942aae432. It is a follow-up harness
for the native CMake/libFuzzer path, separate from target discovery and from
any vulnerability report.

The 130-byte input consists of:

| Offset | Length | Value |
| --- | ---: | --- |
| 0 | 32 | Prover ID |
| 32 | 33 | Compressed secp256k1 public point |
| 65 | 33 | Compressed Schnorr commitment R |
| 98 | 32 | Big-endian response scalar s |

The harness copies bytes into the library's public structures, creates a fresh
secp256k1 algebra context for each input, calls the verifier, and releases the
context. Inputs shorter than 130 bytes are skipped; trailing bytes are ignored.
It performs no persistent writes or network operations.

Generate the initial corpus with:

    python3 examples/fireblocks/make_schnorr_corpus.py /tmp/fireblocks-schnorr-corpus

The generator writes 15 deterministic inputs. Six are mathematically valid:
the baseline uses secret scalar 1 and nonce 1, and the others vary the ID,
secret, and nonce while recomputing s = nonce - SHA256(ID || R || P) * secret
modulo the secp256k1 order. The other nine exercise malformed points, scalar
boundaries, or mismatched but well-formed values. The seed generator uses only
Python's standard library.

Use schnorr_verify_fuzzer.cpp as the native libFuzzer harness, with the
generated directory as its corpus and a maximum input length of 130 bytes.
Compile against the project's generated cosigner_export.h, public headers,
and libcosigner.so. Defining FIREBLOCKS_SCHNORR_REPLAY instead of linking
libFuzzer builds a single-input replay executable; it prints the verifier's
status and exits 0 only for ZKP_SUCCESS.

Validation against the pinned ARM64 library (Clang 18, ASan and sanitizer
coverage): all six valid seeds returned ZKP_SUCCESS (0). The malformed
public point, malformed commitment, and mismatched public point samples
returned verification failure -4. This confirms the seed format reaches the
actual verifier rather than just passing a local mathematical check.
