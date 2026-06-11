"""
Core enrollment and unlock logic for tessera.

enroll(): Create a new vault protecting a MEK with Shamir secret sharing and
          blinded shares.
unlock(): Attempt to recover the MEK from a vault using provided answers.

Security invariants enforced here:
1. Single oracle: only the XChaCha20-Poly1305 tag checks correctness (no
   per-field checks).
2. Argon2id called exactly M times per unlock (Phase 1), cached, NEVER in loop.
3. c_i = (share_i + r_i) % P with r_i uniform mod P.
4. r_i derived from ≥64 bytes of Argon2id output.
5. No early-out on secret comparisons; rely only on the AEAD tag.
6. Failure is opaque: return None, no count/index info.
7. Best-effort zeroization of secret material.
"""

from __future__ import annotations

import itertools
import math
import os
import secrets
from typing import Optional

from .aead import aead_wrap, aead_unwrap, NONCE_BYTES
from .errors import InvalidParamsError
from .field import P, poly_eval, lagrange_interpolate_at_zero
from .kdf import argon2id_hash, reduce_mod_p, derive_kek
from .params import Params
from .processor import FieldProcessor
from .state import FieldEntry, PublicState


def enroll(
    mek: bytes,
    answers: list,
    processors: list[FieldProcessor],
    threshold: int,
    params: Params | None = None,
) -> PublicState:
    """
    Enroll a new vault.

    Args:
        mek:        The plaintext Media/Master Encryption Key to protect.
                    Must be bytes. Length is unrestricted (the AEAD handles it).
        answers:    List of M answers (one per field).
        processors: List of M FieldProcessor objects (one per field).
                    Must match len(answers).
        threshold:  Minimum number of correct answers needed to unlock (t).
        params:     Vault parameters. Uses defaults if None.

    Returns:
        PublicState containing all public data needed to unlock the vault.
        All secret material is zeroized before returning (best-effort).

    Raises:
        InvalidParamsError: if parameters are invalid.
        ValueError: if validation fails.
    """
    if params is None:
        params = Params()

    M = len(answers)

    # --- Validation ---
    if M < 1:
        raise InvalidParamsError("At least one answer is required")
    if len(processors) != M:
        raise InvalidParamsError(
            f"Number of processors ({len(processors)}) must match "
            f"number of answers ({M})"
        )
    if not (1 <= threshold <= M):
        raise ValueError(
            f"threshold must be in [1, M={M}], got {threshold}"
        )
    num_subsets = math.comb(M, threshold)
    if num_subsets > params.max_subsets:
        raise ValueError(
            f"C({M}, {threshold}) = {num_subsets} exceeds max_subsets "
            f"= {params.max_subsets}. Reduce M or increase threshold."
        )
    # Security invariant: hash_len must be ≥64 bytes to ensure bias ≤ 2^-256.
    if params.argon2.hash_len < 64:
        raise ValueError(
            f"argon2.hash_len must be ≥ 64, got {params.argon2.hash_len}. "
            "Fewer bytes would produce bias > 2^-256 when reduced mod P."
        )

    # --- Step 1: Pick random Shamir secret S ---
    # Security note: S is a Python int; Python ints cannot be reliably
    # zeroized because they are immutable objects. We document this caveat
    # and zeroize what we can (bytearray versions of derived keys).
    S = secrets.randbelow(P)

    # --- Step 2: Build degree-(t-1) polynomial with f(0) = S ---
    # coeffs[0] = S (constant term), coeffs[1..t-1] = random
    coeffs = [S] + [secrets.randbelow(P) for _ in range(threshold - 1)]

    # --- Step 3: Enroll each answer ---
    field_entries: list[FieldEntry] = []

    for i, (answer, processor) in enumerate(zip(answers, processors), start=1):
        # x_i = i (1-based, never 0)
        x_i = i

        # Call processor to get public helper and secret stable bytes
        helper_i, w_i = processor.enroll(answer)
        # w_i is secret: the canonical representation of the answer

        # Argon2id blinding: derive r_i
        salt_i = os.urandom(16)
        # Security invariant: Argon2id called with hash_len ≥ 64 bytes
        # so that r_i is statistically indistinguishable from uniform mod P.
        hash_bytes = argon2id_hash(
            password=w_i if isinstance(w_i, bytes) else w_i.encode("utf-8"),
            salt=salt_i,
            argon2_params=params.argon2,
        )
        # Security invariant: ≥64 bytes → bias ≤ 2^-256
        r_i = reduce_mod_p(hash_bytes)

        # Evaluate polynomial at x_i to get the raw share
        share_i = poly_eval(coeffs, x_i, P)

        # Security invariant: c_i = (share_i + r_i) % P
        # c_i is the blinded share stored publicly. share_i and r_i are discarded.
        c_i = (share_i + r_i) % P

        field_entries.append(
            FieldEntry(x=x_i, salt=salt_i, helper=helper_i, c=c_i)
        )

        # Best-effort zeroization of secret values derived as bytearrays
        w_i_ba = bytearray(w_i if isinstance(w_i, bytes) else w_i.encode("utf-8"))
        w_i_ba[:] = b"\x00" * len(w_i_ba)
        del w_i_ba
        hash_ba = bytearray(hash_bytes)
        hash_ba[:] = b"\x00" * len(hash_ba)
        del hash_ba
        # share_i and r_i are Python ints — cannot truly zeroize.
        del share_i, r_i

    # --- Step 4: KDF salt ---
    kdf_salt = os.urandom(16)

    # --- Step 5: Derive KEK from S ---
    # Security note: S is a Python int; the bytearray IKM is zeroized in derive_kek.
    kek_ba = bytearray(
        derive_kek(S, kdf_salt, params.kdf_context)
    )

    # --- Step 6: Nonce ---
    nonce = os.urandom(NONCE_BYTES)

    # --- Step 7: Build PublicState for AAD (without ct/tag) ---
    # We need ct and tag placeholders to build the state struct, but AAD
    # is computed before encryption so ct/tag are NOT in the AAD.
    state = PublicState(
        fields=field_entries,
        threshold=threshold,
        kdf_salt=kdf_salt,
        kdf_context=params.kdf_context,
        argon2=params.argon2,
        nonce=nonce,
        ct=b"",   # placeholder — not in AAD
        tag=b"",  # placeholder — not in AAD
    )

    # --- Step 8: Compute AAD and encrypt MEK ---
    aad = state.compute_aad()
    ct, tag = aead_wrap(bytes(kek_ba), nonce, mek, aad)

    # --- Step 9: Final state with ct/tag ---
    state.ct = ct
    state.tag = tag

    # Best-effort zeroization of KEK
    # CPython caveat: the underlying C buffer may have been copied before
    # this overwrite. Python ints (S, coeffs) cannot be zeroized.
    kek_ba[:] = b"\x00" * len(kek_ba)
    del kek_ba

    # Zeroize polynomial coefficients as much as possible (Python ints — best effort)
    del S, coeffs

    return state


def unlock(
    state: PublicState,
    answers: list,
    processors: list[FieldProcessor],
    reliability_order: list[int] | None = None,
) -> bytes | None:
    """
    Attempt to unlock a vault and recover the MEK.

    Args:
        state:             PublicState from enrollment.
        answers:           List of M answers (or None for missing answers).
                           Must match len(state.fields).
        processors:        List of M FieldProcessor objects (same as enrollment).
        reliability_order: Optional list of 0-based field indices, most reliable
                           first. Reorders subset enumeration for faster success
                           on reliable answers. Does not affect correctness.

    Returns:
        MEK bytes on success, or None if threshold is not met or any tampering
        is detected.

    Security invariants:
    - Argon2id called exactly M times in Phase 1, results cached.
      NEVER called inside the subset loop (Phase 2).
    - Single oracle: only the XChaCha20-Poly1305 tag determines correctness.
    - Failure is opaque: returns None regardless of how many/which fields matched.
    """
    M = len(state.fields)
    if len(answers) != M:
        return None
    if len(processors) != M:
        return None

    # --- Phase 1: Compute all (x_i, y_i) points ---
    # Security invariant: Argon2id called exactly ONCE per field here, results
    # cached in `points`. The subset loop (Phase 2) MUST NOT call Argon2id.
    points: list[tuple[int, int]] = []
    for fe, answer, processor in zip(state.fields, answers, processors):
        # Missing answers → b"" (consistent wrong value; no crash)
        # Security invariant: None answers produce wrong r_i' deterministically
        # without short-circuiting or crashing.
        w_i_prime = processor.recover(fe.helper, answer)

        # Security invariant: Argon2id called exactly M times total (here, Phase 1).
        hash_bytes = argon2id_hash(
            password=w_i_prime,
            salt=fe.salt,
            argon2_params=state.argon2,
        )
        r_i_prime = reduce_mod_p(hash_bytes)

        # Recover candidate share: y_i = (c_i - r_i') mod P
        y_i = (fe.c - r_i_prime) % P

        points.append((fe.x, y_i))

        # Best-effort zeroization
        w_i_ba = bytearray(w_i_prime)
        w_i_ba[:] = b"\x00" * len(w_i_ba)
        del w_i_ba
        hash_ba = bytearray(hash_bytes)
        hash_ba[:] = b"\x00" * len(hash_ba)
        del hash_ba
        del r_i_prime

    # --- Optional: reorder points for reliability_order ---
    # This does not change correctness; it biases which subsets are tried first
    # so that subsets of reliable fields are attempted before noisy ones.
    if reliability_order is not None:
        # Build a priority: lower index in reliability_order → higher priority
        priority = {idx: rank for rank, idx in enumerate(reliability_order)}
        # Points not in reliability_order get lowest priority (rank = M)
        points_with_priority = [
            (priority.get(orig_idx, M), pt)
            for orig_idx, pt in enumerate(points)
        ]
        points_with_priority.sort(key=lambda x: x[0])
        points = [pt for _, pt in points_with_priority]

    # --- Phase 2: Subset enumeration ---
    # Security invariant: NO Argon2id calls in this loop.
    # Security invariant: single oracle — only the AEAD tag check here.
    # Security invariant: no early-out on wrong subsets beyond GCM returning None.
    aad = state.compute_aad()
    t = state.threshold

    for subset in itertools.combinations(points, t):
        # Recover candidate Shamir secret
        try:
            s_prime = lagrange_interpolate_at_zero(list(subset), P)
        except ValueError:
            continue

        # Derive candidate KEK
        kek_candidate_ba = bytearray(
            derive_kek(s_prime, state.kdf_salt, state.kdf_context)
        )

        # Attempt decryption — single oracle
        # Security invariant: aead_unwrap returns None on tag mismatch,
        # never raises an exception that reveals which subset was tried.
        mek = aead_unwrap(
            bytes(kek_candidate_ba),
            state.nonce,
            state.ct,
            state.tag,
            aad,
        )

        # Zeroize candidate KEK
        kek_candidate_ba[:] = b"\x00" * len(kek_candidate_ba)
        del kek_candidate_ba

        if mek is not None:
            return mek
        # Security invariant: do NOT break or return information about partial
        # matches. Continue iterating silently.

    # Security invariant: opaque failure — return None without any count/index info.
    return None
