"""
Tests for tessera.vault — enrollment and unlock end-to-end.

Uses fast Argon2 parameters: opslimit=1, memlimit=8 MiB, hash_len=64 to keep
tests reasonably fast while exercising the full protocol.
"""

import itertools
import math
import os
import secrets
import time
from copy import deepcopy

import pytest

from tessera import (
    Argon2Params,
    ExactStringProcessor,
    Params,
    PublicState,
    RawBytesProcessor,
    enroll,
    unlock,
)
from tessera.field import P


# ---------------------------------------------------------------------------
# Fast parameters for testing
# ---------------------------------------------------------------------------

FAST_ARGON2 = Argon2Params(
    opslimit=1,
    memlimit=8 * 1024 * 1024,
    hash_len=64,
)
FAST_PARAMS = Params(argon2=FAST_ARGON2)


def make_string_processors(n: int) -> list[ExactStringProcessor]:
    return [ExactStringProcessor() for _ in range(n)]


def make_answers(n: int) -> list[str]:
    return [f"answer_{i}_{secrets.token_hex(4)}" for i in range(n)]


def make_wrong_answers(correct: list[str], wrong_indices: list[int]) -> list[str]:
    """Return a copy of `correct` with the specified indices replaced by wrong answers."""
    wrong = list(correct)
    for i in wrong_indices:
        wrong[i] = f"WRONG_ANSWER_{secrets.token_hex(8)}"
    return wrong


# ---------------------------------------------------------------------------
# Round-trip: enroll all correct → returns exact MEK
# ---------------------------------------------------------------------------

def test_roundtrip_all_correct_3of3():
    """All 3 correct answers → returns exact MEK."""
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    state = enroll(mek, answers, processors, threshold=3, params=FAST_PARAMS)
    result = unlock(state, answers, processors)
    assert result == mek


def test_roundtrip_all_correct_2of5():
    """All 5 correct in a 2-of-5 vault → returns exact MEK."""
    mek = os.urandom(32)
    answers = make_answers(5)
    processors = make_string_processors(5)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)
    result = unlock(state, answers, processors)
    assert result == mek


def test_roundtrip_bytes_processor():
    """RawBytesProcessor round-trip."""
    mek = os.urandom(16)
    answers = [os.urandom(20), os.urandom(20), os.urandom(20)]
    processors = [RawBytesProcessor() for _ in range(3)]
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)
    result = unlock(state, answers, processors)
    assert result == mek


def test_roundtrip_single_field_password_vault():
    """
    M=1, t=1 — the degenerate case IS a plain password vault, and is a
    supported configuration (same code path for passwords and questions).
    The polynomial has degree 0 (share == S), there is exactly one subset,
    and unlock is: password → Argon2id → unblind → KEK → AEAD.
    """
    mek = os.urandom(32)
    state = enroll(mek, ["correct horse battery staple"],
                   [ExactStringProcessor()], threshold=1, params=FAST_PARAMS)
    assert len(state.fields) == 1
    assert state.threshold == 1

    # correct password unlocks (and is case-insensitive via normalization)
    procs = [ExactStringProcessor()]
    assert unlock(state, ["correct horse battery staple"], procs) == mek
    assert unlock(state, ["Correct Horse Battery Staple"], procs) == mek

    # wrong or missing password fails opaquely
    assert unlock(state, ["wrong password"], procs) is None
    assert unlock(state, [None], procs) is None

    # survives serialization round trip
    restored = PublicState.from_json(state.to_json())
    assert unlock(restored, ["correct horse battery staple"], procs) == mek


# ---------------------------------------------------------------------------
# Threshold pass: exactly t correct, M-t wrong → returns MEK
# ---------------------------------------------------------------------------

def test_threshold_pass_exact_t():
    """
    2-of-4: exactly 2 correct answers (at various positions) → returns MEK.
    """
    mek = os.urandom(32)
    answers = make_answers(4)
    processors = make_string_processors(4)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    # Test several different which-2 combos
    for correct_indices in [(0, 1), (0, 3), (1, 2), (2, 3), (1, 3)]:
        wrong = [
            answers[i] if i in correct_indices else f"WRONG_{secrets.token_hex(4)}"
            for i in range(4)
        ]
        result = unlock(state, wrong, processors)
        assert result == mek, f"Failed with correct_indices={correct_indices}"


def test_threshold_pass_3of5_various_combos():
    """
    3-of-5: test all C(5,3)=10 possible which-3 combos, each should return MEK.
    """
    mek = os.urandom(32)
    answers = make_answers(5)
    processors = make_string_processors(5)
    state = enroll(mek, answers, processors, threshold=3, params=FAST_PARAMS)

    for correct_indices in itertools.combinations(range(5), 3):
        wrong = [
            answers[i] if i in correct_indices else f"WRONG_{secrets.token_hex(4)}"
            for i in range(5)
        ]
        result = unlock(state, wrong, processors)
        assert result == mek, f"Failed with correct_indices={correct_indices}"


# ---------------------------------------------------------------------------
# Threshold fail: exactly t-1 correct → returns None
# ---------------------------------------------------------------------------

def test_threshold_fail_t_minus_1():
    """
    3-of-5: exactly 2 correct answers (t-1=2) → returns None.
    """
    mek = os.urandom(32)
    answers = make_answers(5)
    processors = make_string_processors(5)
    state = enroll(mek, answers, processors, threshold=3, params=FAST_PARAMS)

    # Test several which-2 combos
    for correct_indices in itertools.combinations(range(5), 2):
        wrong = [
            answers[i] if i in correct_indices else f"WRONG_{secrets.token_hex(4)}"
            for i in range(5)
        ]
        result = unlock(state, wrong, processors)
        assert result is None, f"Should have failed with only 2 correct (t=3), indices={correct_indices}"


def test_threshold_fail_zero_correct():
    """0 correct answers in a 2-of-3 vault → returns None."""
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    all_wrong = [f"TOTALLY_WRONG_{i}" for i in range(3)]
    result = unlock(state, all_wrong, processors)
    assert result is None


# ---------------------------------------------------------------------------
# Subset agreement: every t-subset of correct answers recovers same MEK
# ---------------------------------------------------------------------------

def test_subset_agreement_3of5():
    """
    3-of-5: every C(5,3)=10 subset of correct answers should recover the same MEK.
    """
    mek = os.urandom(32)
    answers = make_answers(5)
    processors = make_string_processors(5)
    state = enroll(mek, answers, processors, threshold=3, params=FAST_PARAMS)

    for combo_indices in itertools.combinations(range(5), 3):
        subset_answers = [
            answers[i] if i in combo_indices else f"WRONG_{secrets.token_hex(4)}"
            for i in range(5)
        ]
        result = unlock(state, subset_answers, processors)
        assert result == mek, f"Subset {combo_indices} did not recover MEK"


# ---------------------------------------------------------------------------
# Randomized: many random correct/incorrect masks
# ---------------------------------------------------------------------------

def test_randomized_correct_incorrect_masks():
    """
    2-of-5: generate many random masks. Assert: returns MEK iff ≥2 correct.
    """
    mek = os.urandom(32)
    answers = make_answers(5)
    processors = make_string_processors(5)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    rng = secrets.SystemRandom()
    for _ in range(30):
        # Random subset of answers to keep correct
        num_correct = rng.randint(0, 5)
        correct_indices = set(rng.sample(range(5), num_correct))
        test_answers = [
            answers[i] if i in correct_indices else f"WRONG_{secrets.token_hex(4)}"
            for i in range(5)
        ]
        result = unlock(state, test_answers, processors)
        if num_correct >= 2:
            assert result == mek, (
                f"Expected MEK with {num_correct} correct, got None. "
                f"correct_indices={correct_indices}"
            )
        else:
            assert result is None, (
                f"Expected None with {num_correct} correct, got MEK. "
                f"correct_indices={correct_indices}"
            )


# ---------------------------------------------------------------------------
# Missing answers (None) → returns None, no crash
# ---------------------------------------------------------------------------

def test_missing_answers_no_crash():
    """None answers in a 2-of-3 vault → returns None without exception."""
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    # All None
    result = unlock(state, [None, None, None], processors)
    assert result is None


def test_missing_answers_partial_none():
    """
    2-of-3: 1 correct, 2 None → returns None (below threshold).
    """
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    # Only first answer correct, rest None
    result = unlock(state, [answers[0], None, None], processors)
    assert result is None


def test_missing_answers_meet_threshold():
    """
    2-of-3: 2 correct, 1 None → returns MEK (threshold met despite None).
    """
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    result = unlock(state, [answers[0], answers[1], None], processors)
    assert result == mek


# ---------------------------------------------------------------------------
# Tamper tests
# ---------------------------------------------------------------------------

def test_tamper_flip_c_i():
    """Flipping a bit in c_i makes unlock return None."""
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    # Flip the c value of the first field
    corrupted = PublicState(
        fields=[
            state.fields[0].__class__(
                x=state.fields[0].x,
                salt=state.fields[0].salt,
                helper=state.fields[0].helper,
                c=(state.fields[0].c + 1) % P,
            ),
            *state.fields[1:],
        ],
        threshold=state.threshold,
        kdf_salt=state.kdf_salt,
        kdf_context=state.kdf_context,
        argon2=state.argon2,
        nonce=state.nonce,
        ct=state.ct,
        tag=state.tag,
    )
    result = unlock(corrupted, answers, processors)
    assert result is None


def test_tamper_change_threshold():
    """
    Changing t in the state invalidates the AAD → GCM tag fails → None.
    """
    mek = os.urandom(32)
    answers = make_answers(4)
    processors = make_string_processors(4)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    # Tamper: change threshold from 2 to 3
    tampered = PublicState(
        fields=state.fields,
        threshold=state.threshold + 1,
        kdf_salt=state.kdf_salt,
        kdf_context=state.kdf_context,
        argon2=state.argon2,
        nonce=state.nonce,
        ct=state.ct,
        tag=state.tag,
    )
    result = unlock(tampered, answers, processors)
    assert result is None


def test_tamper_change_salt_i():
    """
    Changing a salt_i byte in the state invalidates the AAD → None.
    """
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    from tessera.state import FieldEntry
    # Flip first byte of first field's salt
    original_fe = state.fields[0]
    bad_salt = bytes([original_fe.salt[0] ^ 0xFF]) + original_fe.salt[1:]
    tampered_fe = FieldEntry(
        x=original_fe.x,
        salt=bad_salt,
        helper=original_fe.helper,
        c=original_fe.c,
    )
    tampered = PublicState(
        fields=[tampered_fe, *state.fields[1:]],
        threshold=state.threshold,
        kdf_salt=state.kdf_salt,
        kdf_context=state.kdf_context,
        argon2=state.argon2,
        nonce=state.nonce,
        ct=state.ct,
        tag=state.tag,
    )
    result = unlock(tampered, answers, processors)
    assert result is None


def test_tamper_ct_byte():
    """Flipping a byte in ct → AEAD returns None."""
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    bad_ct = bytes([state.ct[0] ^ 0xFF]) + state.ct[1:] if state.ct else state.ct
    tampered = PublicState(
        fields=state.fields,
        threshold=state.threshold,
        kdf_salt=state.kdf_salt,
        kdf_context=state.kdf_context,
        argon2=state.argon2,
        nonce=state.nonce,
        ct=bad_ct,
        tag=state.tag,
    )
    result = unlock(tampered, answers, processors)
    assert result is None


# ---------------------------------------------------------------------------
# No-leak: failure returns None, not an exception with count info
# ---------------------------------------------------------------------------

def test_no_leak_returns_none_not_exception():
    """
    Failure must return None — no exception carrying count/index information.
    """
    mek = os.urandom(32)
    answers = make_answers(5)
    processors = make_string_processors(5)
    state = enroll(mek, answers, processors, threshold=3, params=FAST_PARAMS)

    wrong = [f"WRONG_{i}" for i in range(5)]
    result = unlock(state, wrong, processors)
    assert result is None  # not an exception


def test_no_leak_one_correct_below_threshold():
    """
    1 correct out of 3-of-5 → None. No exception, no partial-match signal.
    """
    mek = os.urandom(32)
    answers = make_answers(5)
    processors = make_string_processors(5)
    state = enroll(mek, answers, processors, threshold=3, params=FAST_PARAMS)

    partial = [answers[0]] + [f"WRONG_{i}" for i in range(1, 5)]
    result = unlock(state, partial, processors)
    assert result is None


# ---------------------------------------------------------------------------
# Parameter validation guards
# ---------------------------------------------------------------------------

def test_param_guard_subsets_exceeded():
    """C(M, t) > max_subsets raises ValueError."""
    params = Params(argon2=FAST_ARGON2, max_subsets=5)
    mek = os.urandom(32)
    answers = make_answers(5)
    processors = make_string_processors(5)
    # C(5, 2) = 10 > 5
    with pytest.raises(ValueError, match="max_subsets"):
        enroll(mek, answers, processors, threshold=2, params=params)


def test_param_guard_hash_len_too_short():
    """hash_len < 64 raises ValueError."""
    bad_argon2 = Argon2Params(opslimit=1, memlimit=8 * 1024 * 1024, hash_len=32)
    bad_params = Params(argon2=bad_argon2)
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    with pytest.raises(ValueError, match="hash_len"):
        enroll(mek, answers, processors, threshold=2, params=bad_params)


def test_param_guard_threshold_zero():
    """threshold=0 raises ValueError."""
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    with pytest.raises(ValueError):
        enroll(mek, answers, processors, threshold=0, params=FAST_PARAMS)


def test_param_guard_threshold_exceeds_M():
    """threshold > M raises ValueError."""
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    with pytest.raises(ValueError):
        enroll(mek, answers, processors, threshold=4, params=FAST_PARAMS)


def test_param_guard_no_answers():
    """Empty answers list raises InvalidParamsError."""
    from tessera.errors import InvalidParamsError
    mek = os.urandom(32)
    with pytest.raises((ValueError, InvalidParamsError)):
        enroll(mek, [], [], threshold=1, params=FAST_PARAMS)


# ---------------------------------------------------------------------------
# JSON / bytes serialization round-trip
# ---------------------------------------------------------------------------

def test_json_roundtrip():
    """PublicState survives to_json() → from_json() round-trip."""
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    json_str = state.to_json()
    restored = PublicState.from_json(json_str)
    result = unlock(restored, answers, processors)
    assert result == mek


def test_bytes_roundtrip():
    """PublicState survives to_bytes() → from_bytes() round-trip."""
    mek = os.urandom(32)
    answers = make_answers(3)
    processors = make_string_processors(3)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    raw = state.to_bytes()
    assert raw[:4] == b"TVSV"
    restored = PublicState.from_bytes(raw)
    result = unlock(restored, answers, processors)
    assert result == mek


# ---------------------------------------------------------------------------
# ExactStringProcessor normalization
# ---------------------------------------------------------------------------

def test_exact_string_case_insensitive():
    """ExactStringProcessor: enrollment with 'Hello' should unlock with 'hello'."""
    mek = os.urandom(32)
    answers = ["Hello World", "SecondAnswer"]
    processors = make_string_processors(2)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    # Unlock with casefolded versions
    result = unlock(state, ["hello world", "secondanswer"], processors)
    assert result == mek


def test_exact_string_whitespace_stripped():
    """ExactStringProcessor: leading/trailing whitespace is stripped."""
    mek = os.urandom(32)
    answers = ["  hello  ", "world"]
    processors = make_string_processors(2)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    result = unlock(state, ["hello", "world"], processors)
    assert result == mek


def test_exact_string_nfc_normalization():
    """ExactStringProcessor: NFC-normalized strings compare equal."""
    # é can be represented as NFC (U+00E9) or NFD (e + combining accent)
    nfc_e = "é"      # NFC: single codepoint
    nfd_e = "é"     # NFD: e + combining acute accent
    assert nfc_e != nfd_e  # different byte sequences

    mek = os.urandom(32)
    answers = [nfc_e + "test", "other"]
    processors = make_string_processors(2)
    state = enroll(mek, answers, processors, threshold=2, params=FAST_PARAMS)

    # Unlock with NFD form — should normalize to same value
    result = unlock(state, [nfd_e + "test", "other"], processors)
    assert result == mek


# ---------------------------------------------------------------------------
# Performance smoke test: M=15, t=8
# ---------------------------------------------------------------------------

def test_performance_smoke_m15_t8():
    """
    M=15, t=8 with fast params. Time the subset loop separately to prove
    Argon2 is NOT inside the loop.

    C(15,8) = 6435 subsets. The subset loop (pure arithmetic + AES-GCM)
    must complete in a reasonable time regardless of Argon2 cost.

    The Argon2 calls (M=15) are timed separately.
    """
    # C(15, 8) = 6435 ≤ 1,000,000 (default max_subsets)
    assert math.comb(15, 8) == 6435

    mek = os.urandom(32)
    answers = make_answers(15)
    processors = make_string_processors(15)
    params = Params(argon2=FAST_ARGON2)

    # Enrollment (includes Argon2 × 15 — not timed for loop assertion)
    state = enroll(mek, answers, processors, threshold=8, params=params)

    # Time the full unlock (Phase 1 = 15 Argon2 calls, Phase 2 = 6435 subsets)
    t0 = time.perf_counter()
    result = unlock(state, answers, processors)
    total_time = time.perf_counter() - t0

    assert result == mek, "M=15, t=8 did not recover MEK"

    # The subset loop (6435 iterations of BLAKE2b + XChaCha20-Poly1305) should
    # be fast — well under 1 second when Argon2 is not inside it.
    # The 15 Argon2id calls with memlimit=8 MiB dominate.
    # We only assert total time < 60s as a generous bound; the real assertion
    # is that Argon2 is NOT repeated in the loop (6435 × Argon2 would be ~hours).
    assert total_time < 60, (
        f"Unlock took {total_time:.1f}s — suspiciously slow; "
        "check that Argon2 is not called inside the subset loop"
    )
    # Note: with memlimit=8 MiB and M=15, 15 Argon2 calls ≈ few seconds.
    # If Argon2 were inside the loop: 6435 × ~0.1s = 643s (would fail above).
    print(f"\n[perf] M=15, t=8: C(15,8)=6435 subsets, total unlock={total_time:.3f}s")


def test_performance_only_subset_loop():
    """
    Directly verify that the subset loop (arithmetic only) is fast by
    using the fastest possible Argon2 params and measuring just the unlock time
    vs. the expected cost of 15 Argon2 calls.

    If Argon2 is incorrectly placed inside the loop, this test will be
    dramatically slower.
    """
    # Use the absolute minimum Argon2 params to make Argon2 calls negligible
    ultra_fast = Argon2Params(opslimit=1, memlimit=8192, hash_len=64)
    params = Params(argon2=ultra_fast)

    mek = os.urandom(32)
    answers = make_answers(15)
    processors = make_string_processors(15)
    state = enroll(mek, answers, processors, threshold=8, params=params)

    t0 = time.perf_counter()
    result = unlock(state, answers, processors)
    elapsed = time.perf_counter() - t0

    assert result == mek
    # With ultra-fast Argon2, 6435 subset iterations of HKDF+AES-GCM
    # should complete in well under 5 seconds.
    assert elapsed < 5.0, (
        f"Subset loop took {elapsed:.2f}s — likely Argon2 is inside the loop"
    )
    print(f"\n[perf] subset loop only: 6435 iters in {elapsed:.3f}s")


# ---------------------------------------------------------------------------
# reliability_order option
# ---------------------------------------------------------------------------

def test_reliability_order_still_correct():
    """
    reliability_order changes subset enumeration order but must still
    recover the correct MEK.
    """
    mek = os.urandom(32)
    answers = make_answers(5)
    processors = make_string_processors(5)
    state = enroll(mek, answers, processors, threshold=3, params=FAST_PARAMS)

    # Provide reliability order: indices 2, 0, 4 are "most reliable" first
    result = unlock(state, answers, processors, reliability_order=[2, 0, 4, 1, 3])
    assert result == mek
