"""
Verify the Python reference reproduces every known-answer vector in
tests/vectors/kat.json. This guards against drift between the generator and
the live code, and doubles as the exact set of checks each port (TS/Dart)
must pass.
"""

import json
import os

import pytest

from tessera import PublicState, ExactStringProcessor, unlock
from tessera.aead import aead_wrap, aead_unwrap
from tessera.field import P, lagrange_interpolate_at_zero, poly_eval
from tessera.kdf import argon2id_hash, derive_key, reduce_mod_p
from tessera.params import Argon2Params

from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_state as _SSState,
    crypto_secretstream_xchacha20poly1305_init_pull as _ss_init_pull,
    crypto_secretstream_xchacha20poly1305_pull as _ss_pull,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL as _TAG_FINAL,
)

H = bytes.fromhex

_KAT_PATH = os.path.join(os.path.dirname(__file__), "vectors", "kat.json")
with open(_KAT_PATH, encoding="utf-8") as _f:
    KAT = json.load(_f)


@pytest.mark.parametrize("case", KAT["argon2id"])
def test_argon2id(case):
    out = argon2id_hash(
        H(case["password_hex"]),
        H(case["salt_hex"]),
        Argon2Params(opslimit=case["opslimit"], memlimit=case["memlimit"], hash_len=case["hash_len"]),
    )
    assert out.hex() == case["output_hex"]


@pytest.mark.parametrize("case", KAT["reduce_mod_p"])
def test_reduce_mod_p(case):
    assert str(reduce_mod_p(H(case["input_hex"]))) == case["output_decimal"]


@pytest.mark.parametrize("case", KAT["blake2b_kdf"])
def test_blake2b_kdf(case):
    key = derive_key(H(case["secret_hex"]), H(case["salt_hex"]), H(case["domain_hex"]))
    assert key.hex() == case["key_hex"]


@pytest.mark.parametrize("case", KAT["xchacha20poly1305"])
def test_xchacha20poly1305(case):
    key, nonce = H(case["key_hex"]), H(case["nonce_hex"])
    pt, aad = H(case["plaintext_hex"]), H(case["aad_hex"])
    ct, tag = aead_wrap(key, nonce, pt, aad)
    assert ct.hex() == case["ciphertext_hex"]
    assert tag.hex() == case["tag_hex"]
    assert aead_unwrap(key, nonce, ct, tag, aad) == pt


def test_field():
    f = KAT["field"]
    assert str(P) == f["P_decimal"]
    coeffs = [int(c) for c in f["poly_eval"]["coeffs_decimal"]]
    for pt in f["poly_eval"]["points"]:
        assert str(poly_eval(coeffs, pt["x"], P)) == pt["result_decimal"]
    pts = [(x, int(y)) for x, y in f["lagrange_interpolate_at_zero"]["points"]]
    assert str(lagrange_interpolate_at_zero(pts, P)) == f["lagrange_interpolate_at_zero"]["secret_decimal"]


def test_aad():
    state = PublicState.from_json(json.dumps(KAT["aad"]["state_json"]))
    assert state.compute_aad().hex() == KAT["aad"]["aad_hex"]


def test_secretstream_decrypt():
    v = KAT["secretstream_decrypt"]
    st = _SSState()
    _ss_init_pull(st, H(v["header_hex"]), H(v["key_hex"]))
    for ch in v["chunks"]:
        msg, tag = _ss_pull(st, H(ch["ciphertext_hex"]), H(ch["ad_hex"]))
        assert msg.hex() == ch["plaintext_hex"]
        is_final = tag == _TAG_FINAL
        assert is_final == (ch["tag"] == "FINAL")


def test_vault_unlock():
    v = KAT["vault_unlock"]
    state = PublicState.from_json(json.dumps(v["state_json"]))
    procs = [ExactStringProcessor() for _ in v["answers"]]
    # One wrong answer, still >= threshold correct.
    answers = list(v["answers"])
    answers[1] = "WRONG"
    assert unlock(state, answers, procs).hex() == v["mek_hex"]


@pytest.mark.parametrize("case", KAT["string_normalization"])
def test_string_normalization(case):
    proc = ExactStringProcessor()
    raw = bytes.fromhex(case["input_utf8_hex"]).decode("utf-8")
    assert proc.recover(b"", raw).hex() == case["normalized_utf8_hex"]


def test_vault_unlock_unicode():
    v = KAT["vault_unlock_unicode"]
    state = PublicState.from_json(json.dumps(v["state_json"]))
    procs = [ExactStringProcessor() for _ in v["answers"]]
    assert unlock(state, v["answers"], procs).hex() == v["mek_hex"]
    # NFC + casefold variants must produce identical blinding -> same MEK.
    assert unlock(state, v["alt_answers"], procs).hex() == v["mek_hex"]


def test_vault_unlock_single_field():
    # M=1/t=1 degenerate case: a plain password vault on the same code path.
    v = KAT["vault_unlock_single_field"]
    state = PublicState.from_json(json.dumps(v["state_json"]))
    procs = [ExactStringProcessor()]
    assert unlock(state, v["answers"], procs).hex() == v["mek_hex"]
    assert unlock(state, ["WRONG"], procs) is None
