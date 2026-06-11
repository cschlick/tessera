"""
Key derivation functions for tessera (libsodium / PyNaCl backend).

- argon2id_hash: slow memory-hard hash for answer blinding (libsodium
  crypto_pwhash, Argon2id v1.3).
- reduce_mod_p: reduce ≥64 byte hash output to field element.
- derive_kek / derive_key: BLAKE2b-256 KDF for keys derived from a secret.

Porting note (for the TS/Dart reimplementations):
    All three primitives here are libsodium functions, so the reference
    behavior is defined by libsodium, not by any language binding:
      - Argon2id: crypto_pwhash with alg = ARGON2ID13. libsodium FIXES
        parallelism (lanes) = 1; only opslimit (iterations) and memlimit
        (bytes) vary. Any port MUST use the same opslimit/memlimit and a
        ≥64-byte output, or the derived field elements will differ.
      - KDF: BLAKE2b-256 over the byte string (domain || salt || secret).
        This is plain crypto_generichash with a 32-byte digest — the most
        widely available BLAKE2b form across libsodium bindings. The salt
        and domain are folded into the *message*, not BLAKE2b's native
        salt/personal slots, specifically so ports only need basic
        generichash.
"""

from nacl.bindings import (
    crypto_pwhash_alg,
    crypto_pwhash_ALG_ARGON2ID13,
    crypto_generichash_blake2b_salt_personal as _blake2b,
)

from .field import P
from .params import Argon2Params

_KEK_BYTES = 32


def argon2id_hash(password: bytes, salt: bytes, argon2_params: Argon2Params) -> bytes:
    """
    Compute Argon2id (v1.3) hash with libsodium's crypto_pwhash.

    Returns argon2_params.hash_len bytes.

    Security invariant: hash_len must be ≥64 bytes so that when reduced mod P
    the bias is ≤ 2^-256 (since |output_space| ≥ 2^512 >> P ≈ 2^256).

    Note: salt must be exactly 16 bytes (libsodium crypto_pwhash_SALTBYTES).
    """
    return crypto_pwhash_alg(
        argon2_params.hash_len,
        password,
        salt,
        argon2_params.opslimit,
        argon2_params.memlimit,
        crypto_pwhash_ALG_ARGON2ID13,
    )


def reduce_mod_p(hash_bytes: bytes) -> int:
    """
    Reduce a ≥64-byte hash output to a field element in [0, P).

    Security invariant: MUST be called with ≥64 bytes (≥512 bits) of hash output
    to ensure statistical bias in the result is ≤ 2^-256. Never call with
    32-byte output — that would produce bias of ~2^-1 on the top bit.
    """
    # Security invariant: ≥64 bytes required; validated in enroll() via Params.
    return int.from_bytes(hash_bytes, "big") % P


def derive_key(secret: bytes, salt: bytes, domain: bytes) -> bytes:
    """
    Derive a 32-byte key from a high-entropy secret with BLAKE2b-256.

    key = BLAKE2b-256( domain || salt || secret )

    `domain` provides cross-use separation (a constant per call site); `salt`
    is fixed-length per call site (16 bytes); `secret` is variable-length and
    placed last so the field boundaries are unambiguous. Because the secret is
    uniformly random, a single BLAKE2b pass is a sound KDF (no HKDF extract
    step is needed for uniform input).
    """
    return _blake2b(domain + salt + secret, digest_size=_KEK_BYTES)


def derive_kek(
    secret: int,
    kdf_salt: bytes,
    kdf_context: bytes,
) -> bytes:
    """
    Derive a 32-byte Key Encryption Key from the Shamir secret S.

    KEK = BLAKE2b-256( kdf_context || kdf_salt || S_as_32_bytes )

    Security note: S is a Python int and cannot be reliably zeroized.
    We convert to bytes, derive, and immediately overwrite the bytearray.
    """
    ikm_bytes = bytearray(secret.to_bytes(32, "big"))
    try:
        return derive_key(bytes(ikm_bytes), kdf_salt, kdf_context)
    finally:
        # Best-effort zeroization of IKM bytes.
        # CPython caveat: the underlying C buffer may be copied by the GC
        # or other Python internals before this overwrite occurs.
        ikm_bytes[:] = b"\x00" * len(ikm_bytes)
        del ikm_bytes
