"""
Parameter dataclasses for tessera.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Argon2Params:
    """
    Parameters for libsodium's Argon2id (crypto_pwhash, alg = ARGON2ID13).

    Defaults are conservative for production use:
    - opslimit=3:           3 passes (iterations / "time cost").
    - memlimit=268435456:   256 MiB of memory, in BYTES.
    - hash_len=64:          64 bytes = 512 bits output.

    Note: unlike the raw Argon2 spec, libsodium's crypto_pwhash FIXES the
    parallelism (lanes) at 1, so there is no parallelism parameter here. This
    is intentional and helps cross-implementation determinism (Python / TS /
    Dart all using libsodium agree byte-for-byte).

    Security invariant: hash_len MUST be ≥ 64 bytes.
    A 64-byte (512-bit) output reduced mod P (256-bit prime) has bias ≤ 2^-256,
    which is computationally negligible. A 32-byte output would have bias ~2^0.
    """

    opslimit: int = 3
    memlimit: int = 256 * 1024 * 1024  # 256 MiB, in bytes
    hash_len: int = 64


@dataclass(frozen=True)
class Params:
    """
    Full parameter set for tessera enrollment and unlock.

    argon2: Argon2id parameters used for answer blinding.
    kdf_context: BLAKE2b KDF domain-separation string. Changing this
                 invalidates all existing vaults.
    max_subsets: Upper bound on C(M, t) subset iterations allowed in unlock.
                 Prevents accidentally creating vaults that take years to unlock.
                 Default 1,000,000 subsets.
    """

    argon2: Argon2Params = field(default_factory=Argon2Params)
    kdf_context: bytes = b"tessera/kek/v1"
    max_subsets: int = 1_000_000
