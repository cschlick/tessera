"""
Generate known-answer test (KAT) vectors for tessera.

The Python implementation is the REFERENCE. Running this script regenerates
tests/vectors/kat.json, which the TypeScript and Dart ports must reproduce
byte-for-byte. Each section isolates one primitive or construction so a port
can be validated incrementally (start with argon2id — the hardest to match —
before attempting a full vault_unlock).

Usage:
    python -m tessera.tools.gen_kat        # writes tests/vectors/kat.json
    python tools/gen_kat.py                # same, run from package dir

All byte strings are lowercase hex. Big integers are decimal strings.
"""

from __future__ import annotations

import json
import os
import sys

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tessera.aead import aead_wrap
from tessera.container import CHUNK, MAGIC, VERSION, _container_key
from tessera.field import P, lagrange_interpolate_at_zero, poly_eval
from tessera.kdf import argon2id_hash, derive_key, reduce_mod_p
from tessera.params import Argon2Params, Params
from tessera.processor import ExactStringProcessor
from tessera.state import FieldEntry, PublicState
from tessera.vault import enroll, unlock

from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_state as _SSState,
    crypto_secretstream_xchacha20poly1305_init_push as _ss_init_push,
    crypto_secretstream_xchacha20poly1305_push as _ss_push,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as _TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL as _TAG_FINAL,
)

H = bytes.fromhex


def hx(b: bytes) -> str:
    return b.hex()


def gen_argon2id() -> list:
    cases = []
    # Small/fast cases for routine CI parity. opslimit>=1, memlimit>=8192.
    params = [
        (b"correct horse", H("00112233445566778899aabbccddeeff"), 1, 8192, 64),
        (b"correct horse", H("00112233445566778899aabbccddeeff"), 2, 8 * 1024 * 1024, 64),
        ("pässwörd".encode("utf-8"), H("ffffffffffffffffffffffffffffffff"), 3, 16 * 1024 * 1024, 64),
    ]
    for pw, salt, ops, mem, hlen in params:
        out = argon2id_hash(pw, salt, Argon2Params(opslimit=ops, memlimit=mem, hash_len=hlen))
        cases.append({
            "password_hex": hx(pw),
            "salt_hex": hx(salt),
            "opslimit": ops,
            "memlimit": mem,
            "hash_len": hlen,
            "alg": "argon2id-v1.3",
            "output_hex": hx(out),
        })
    return cases


def gen_reduce_mod_p() -> list:
    cases = []
    for seed in (b"\x00" * 64, bytes(range(64)), b"\xff" * 64):
        cases.append({"input_hex": hx(seed), "output_decimal": str(reduce_mod_p(seed))})
    return cases


def gen_blake2b_kdf() -> list:
    cases = []
    samples = [
        (b"tessera/kek/v1", H("0102030405060708090a0b0c0d0e0f10"), bytes(range(32))),
        (b"tessera/container/v1", H("aabbccddeeff00112233445566778899"), b"short-mek"),
    ]
    for domain, salt, secret in samples:
        key = derive_key(secret, salt, domain)
        cases.append({
            "construction": "BLAKE2b-256(domain || salt || secret)",
            "domain_hex": hx(domain),
            "salt_hex": hx(salt),
            "secret_hex": hx(secret),
            "key_hex": hx(key),
        })
    return cases


def gen_xchacha() -> list:
    key = bytes(range(32))
    nonce = bytes(range(24))
    pt = b"tessera xchacha20-poly1305 test vector"
    aad = b"associated-data"
    ct, tag = aead_wrap(key, nonce, pt, aad)
    return [{
        "key_hex": hx(key),
        "nonce_hex": hx(nonce),
        "plaintext_hex": hx(pt),
        "aad_hex": hx(aad),
        "ciphertext_hex": hx(ct),
        "tag_hex": hx(tag),
    }]


def gen_field() -> dict:
    coeffs = [123456789, 987654321, 555]  # S, a1, a2 (degree 2)
    poly = [{"x": x, "result_decimal": str(poly_eval(coeffs, x, P))} for x in (1, 2, 3, 7)]
    # Interpolate back S from any t=3 points.
    pts = [(x, poly_eval(coeffs, x, P)) for x in (1, 2, 3)]
    secret = lagrange_interpolate_at_zero(pts, P)
    return {
        "P_decimal": str(P),
        "poly_eval": {"coeffs_decimal": [str(c) for c in coeffs], "points": poly},
        "lagrange_interpolate_at_zero": {
            "points": [[x, str(y)] for x, y in pts],
            "secret_decimal": str(secret),
        },
    }


def gen_aad() -> dict:
    # A fully fixed PublicState so the canonical AAD encoding can be checked.
    state = PublicState(
        fields=[
            FieldEntry(x=1, salt=H("00112233445566778899aabbccddeeff"), helper=b"", c=42),
            FieldEntry(x=2, salt=H("ffeeddccbbaa99887766554433221100"), helper=b"hi", c=P - 1),
        ],
        threshold=2,
        kdf_salt=H("0a0b0c0d0e0f10111213141516171819"),
        kdf_context=b"tessera/kek/v1",
        argon2=Argon2Params(opslimit=3, memlimit=256 * 1024 * 1024, hash_len=64),
        nonce=bytes(range(24)),
        ct=b"",
        tag=b"",
    )
    return {"state_json": json.loads(state.to_json()), "aad_hex": hx(state.compute_aad())}


def gen_secretstream() -> dict:
    # Decryption KAT: fixed key + captured header + chunk ciphertexts.
    key = bytes([7]) * 32
    st = _SSState()
    header = _ss_init_push(st, key)
    chunks_pt = [b"first chunk", b"second chunk", b"final chunk"]
    ads = [b"hdr-ad", b"", b""]
    out = []
    for i, (pt, ad) in enumerate(zip(chunks_pt, ads)):
        tag = _TAG_FINAL if i == len(chunks_pt) - 1 else _TAG_MESSAGE
        ct = _ss_push(st, pt, ad, tag)
        out.append({
            "ad_hex": hx(ad),
            "tag": "FINAL" if tag == _TAG_FINAL else "MESSAGE",
            "plaintext_hex": hx(pt),
            "ciphertext_hex": hx(ct),
        })
    return {"key_hex": hx(key), "header_hex": hx(header), "chunks": out}


def gen_vault_unlock() -> dict:
    # Integration KAT: a real serialized vault + answers -> known MEK.
    # enroll() takes the MEK as input, so the MEK is fixed; only internal
    # blinding randomness varies, and the resulting state fully determines
    # unlock. A port must unlock this exact state to this exact MEK.
    mek = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    answers = ["alpha", "bravo", "charlie"]
    procs = [ExactStringProcessor() for _ in answers]
    fast = Params(argon2=Argon2Params(opslimit=2, memlimit=8 * 1024 * 1024, hash_len=64))
    state = enroll(mek, answers, procs, threshold=2, params=fast)
    # self-check
    assert unlock(state, ["alpha", "WRONG", "charlie"], procs) == mek
    return {
        "processor": "ExactStringProcessor",
        "answers": answers,
        "threshold": 2,
        "state_json": json.loads(state.to_json()),
        "mek_hex": hx(mek),
        "note": "Unlock with any 2 of the 3 answers correct must yield mek_hex.",
    }


def gen_string_normalization() -> list:
    # Pins ExactStringProcessor's canonicalization byte-for-byte:
    #   NFC -> strip (Python unicode whitespace) -> casefold -> UTF-8.
    # Note the result is NOT re-normalized after casefold; ports must match.
    from tessera.processor import _normalize_string

    inputs = [
        "  Hello World  ",            # ASCII strip + casefold
        "Straße",                     # ß -> ss (full casefold, not lowercase)
        "Café",                  # precomposed é
        "Café",                 # decomposed e + combining acute -> same as above
        "ΣΊΣΥΦΟΣ",                    # Greek: capital + final-sigma handling
        "İstanbul",                   # dotted capital I -> i + U+0307 (stays decomposed)
        "ﬁre",                   # ﬁ ligature: NFC keeps it, casefold expands to "fi"
        " padded ",         # NBSP is Python-strippable whitespace
        "ǅungla",                     # titlecase digraph DŽ
    ]
    cases = []
    for s in inputs:
        norm = _normalize_string(s)
        cases.append({
            "input_utf8_hex": hx(s.encode("utf-8")),
            "normalized_utf8_hex": hx(norm.encode("utf-8")),
        })
    return cases


def gen_vault_unlock_unicode() -> dict:
    # Integration KAT with non-ASCII answers: normalization feeds Argon2id, so
    # a port with wrong NFC/casefold produces wrong blinding and fails here.
    mek = bytes.fromhex("a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8")
    answers = ["Café", "Straße"]
    procs = [ExactStringProcessor() for _ in answers]
    fast = Params(argon2=Argon2Params(opslimit=2, memlimit=8 * 1024 * 1024, hash_len=64))
    state = enroll(mek, answers, procs, threshold=2, params=fast)
    # Variants that MUST also unlock (normalize to identical bytes).
    alt_answers = ["Café", "STRASSE"]
    assert unlock(state, answers, procs) == mek
    assert unlock(state, alt_answers, procs) == mek
    return {
        "processor": "ExactStringProcessor",
        "answers": answers,
        "alt_answers": alt_answers,
        "threshold": 2,
        "state_json": json.loads(state.to_json()),
        "mek_hex": hx(mek),
        "note": "Both answers and alt_answers must unlock to mek_hex: "
                "decomposed e+combining-acute == precomposed é (NFC), and "
                "STRASSE == Straße (casefold ß->ss).",
    }


def gen_vault_unlock_single_field() -> dict:
    # Degenerate-case KAT: M=1, t=1 — a plain password vault. Pins that the
    # same code path supports passwords (degree-0 polynomial, one subset).
    mek = bytes.fromhex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
    password = "correct horse battery staple"
    procs = [ExactStringProcessor()]
    fast = Params(argon2=Argon2Params(opslimit=2, memlimit=8 * 1024 * 1024, hash_len=64))
    state = enroll(mek, [password], procs, threshold=1, params=fast)
    # self-check, including the opaque-failure side
    assert unlock(state, [password], procs) == mek
    assert unlock(state, ["wrong"], procs) is None
    return {
        "processor": "ExactStringProcessor",
        "answers": [password],
        "threshold": 1,
        "state_json": json.loads(state.to_json()),
        "mek_hex": hx(mek),
        "note": "M=1/t=1 degenerate case: a plain password vault. The correct "
                "password must yield mek_hex; any wrong password must fail.",
    }


def main() -> int:
    kat = {
        "_about": "Known-answer vectors generated from the tessera Python reference.",
        "container_constants": {"magic": MAGIC.decode("ascii"), "version": VERSION, "chunk_bytes": CHUNK},
        "argon2id": gen_argon2id(),
        "reduce_mod_p": gen_reduce_mod_p(),
        "blake2b_kdf": gen_blake2b_kdf(),
        "xchacha20poly1305": gen_xchacha(),
        "field": gen_field(),
        "aad": gen_aad(),
        "secretstream_decrypt": gen_secretstream(),
        "string_normalization": gen_string_normalization(),
        "vault_unlock": gen_vault_unlock(),
        "vault_unlock_single_field": gen_vault_unlock_single_field(),
        "vault_unlock_unicode": gen_vault_unlock_unicode(),
    }
    here = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(here, "..", "tests", "vectors", "kat.json")
    out_path = os.path.abspath(out_path)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(kat, f, indent=2, ensure_ascii=True)
        f.write("\n")
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
