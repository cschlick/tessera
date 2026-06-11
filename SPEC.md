# tessera format & crypto specification (v1)

This document defines tessera precisely enough to reimplement in another
language. The Python package is the **reference**; where this document and the
code disagree, the code (and the vectors it generates) win. Conformance is
checked against `tests/vectors/kat.json` — a port is correct when it
reproduces every vector there.

All multi-byte integers are **big-endian** unless stated. "hex" means
lowercase. Field elements and other large integers are decimal strings in
JSON. Byte fields in JSON are **base64** (standard, with padding).

## 1. Primitives (all from libsodium)

| Use | Primitive | Notes |
|-----|-----------|-------|
| Answer blinding | Argon2id **v1.3** (`crypto_pwhash`, alg=2) | parallelism is FIXED at 1 by libsodium; only `opslimit` (passes) and `memlimit` (bytes) vary. Output length = `hash_len`, **must be ≥ 64**. salt = exactly 16 bytes. |
| Key derivation | BLAKE2b-256 (`crypto_generichash`, 32-byte digest) | unkeyed, over a byte-string message (see §3). |
| MEK wrap | XChaCha20-Poly1305 IETF (`crypto_aead_xchacha20poly1305_ietf`) | 24-byte nonce, 16-byte tag. |
| Container body | secretstream XChaCha20-Poly1305 | 24-byte header, 17-byte per-chunk overhead (`ABYTES`). |

## 2. Finite field

`P = 2**256 - 189` (a 256-bit prime). All Shamir arithmetic is mod P.

- `poly_eval(coeffs, x)`: Horner, `coeffs[0]` is the constant term (secret S).
- `lagrange_interpolate_at_zero(points)`: standard Lagrange at x=0, using
  modular inverse (Fermat or extended Euclid).
- **Normalization rule (critical for ports):** every intermediate result is
  reduced into `[0, P)`. Python's `%` already does this; in languages where
  `%` can return negatives (e.g. JS `BigInt`), apply `((v % P) + P) % P`.

## 3. Key derivation (BLAKE2b)

```
derive_key(secret, salt, domain) = BLAKE2b-256( domain || salt || secret )
```

`domain` and `salt` are fixed-length per call site; `secret` is last so the
boundaries are unambiguous. Two call sites:

- **KEK:** `derive_key(S_as_32_bytes_BE, kdf_salt(16), kdf_context)`,
  default `kdf_context = b"tessera/kek/v1"`.
- **Container key:** `derive_key(MEK, salt(16), b"tessera/container/v1")`.

`reduce_mod_p(h)` = `int.from_bytes(h, "big") % P`, where `h` is the ≥64-byte
Argon2id output. ≥64 bytes keeps the reduction bias ≤ 2⁻²⁵⁶.

## 3a. ExactStringProcessor normalization

String answers are canonicalized before hashing:

```
stable_bytes = UTF-8( casefold( strip( NFC(answer) ) ) )
```

- **NFC**: Unicode canonical composition.
- **strip**: remove leading/trailing code points where Python's
  `str.isspace()` is true (this set differs slightly from other languages'
  trim(); e.g. U+FEFF is NOT stripped).
- **casefold**: Unicode FULL case folding (`str.casefold()`): one-to-many
  expansions apply (ß → ss, ﬁ → fi), final sigma maps Σ/ς → σ.
- The result is **not** re-normalized after casefold.
- A missing answer (`None`/null) yields `b""`.
- helper is always `b""`.

Ports must not approximate with simple lowercasing. The reference tables can
be exported from CPython via `tessera/tools/gen_dart_unicode.py`; parity is
pinned by the `string_normalization` and `vault_unlock_unicode` vectors.

## 4. Enrollment

Given MEK, M answers, M processors, threshold t, and params:

1. `S = random in [0, P)`.
2. Polynomial `f` of degree t−1: `coeffs = [S, r1, …, r_{t-1}]`, each `r_i`
   random in `[0, P)`.
3. For field i (1-based, `x_i = i`):
   - `(helper_i, w_i) = processor.enroll(answer_i)`.
   - `salt_i = 16 random bytes`.
   - `r_i = reduce_mod_p( Argon2id(w_i, salt_i, params.argon2) )`.
   - `share_i = f(x_i)`; **blinded share** `c_i = (share_i + r_i) mod P`.
4. `kdf_salt = 16 random bytes`; `KEK = derive_key(S, kdf_salt, kdf_context)`.
5. `nonce = 24 random bytes`.
6. Build `PublicState` with `ct=b"", tag=b""`, compute `aad = compute_aad()`
   (§6), then `(ct, tag) = XChaCha20-Poly1305(KEK, nonce, MEK, aad)`.
7. Store `ct`, `tag`. Output the `PublicState`.

## 5. Unlock

1. **Phase 1** — for each field, exactly once (cache the result):
   `w_i' = processor.recover(helper_i, answer_i)` (missing answer → `b""`);
   `r_i' = reduce_mod_p( Argon2id(w_i', salt_i, state.argon2) )`;
   candidate point `(x_i, y_i)` with `y_i = (c_i - r_i') mod P`.
   **Argon2id is called exactly M times total and never again.**
2. **Phase 2** — `aad = compute_aad()`. For each t-subset of the points:
   `S' = lagrange_interpolate_at_zero(subset)`;
   `KEK' = derive_key(S', kdf_salt, kdf_context)`;
   `MEK = XChaCha20-Poly1305_decrypt(KEK', nonce, ct, tag, aad)`.
   Return the first MEK that authenticates. The AEAD tag is the **only**
   correctness oracle. If no subset authenticates, return failure (Python:
   `None`) with **no** information about which/how many answers matched.

## 6. Canonical AAD encoding (`compute_aad`)

Deterministic, length-prefixed binary. Covers everything except `ct`/`tag`.

```
[4]   version = 1
[32]  P, big-endian
[4]   M (number of fields)
[4]   t (threshold)
for each field, in order:
    [4]   x_i
    [4]   len(salt_i)   [salt_i]
    [4]   len(helper_i) [helper_i]
    [32]  c_i, big-endian
[4]   len(kdf_salt)    [kdf_salt]
[4]   len(kdf_context) [kdf_context]
[8]   argon2.opslimit
[8]   argon2.memlimit
[4]   argon2.hash_len
[4]   len(nonce)       [nonce]
```

All integers big-endian. `c_i` is always serialized as exactly 32 bytes.
Validate the vector in `kat.json → aad`.

## 7. PublicState JSON

```json
{
  "version": 1,
  "fields": [{"x": 1, "salt": "<b64>", "helper": "<b64>", "c": "<decimal>"}],
  "threshold": 2,
  "kdf_salt": "<b64>",
  "kdf_context": "<b64>",
  "argon2": {"opslimit": 3, "memlimit": 268435456, "hash_len": 64},
  "nonce": "<b64>",
  "ct": "<b64>",
  "tag": "<b64>"
}
```

`c` is a **decimal string** (not a number) to avoid JS 53-bit float loss.
`to_bytes()` wraps this as `b"TVSV" || uint32(len(json)) || json_utf8`.

## 8. Container format

```
magic     4    "TSRA"
version   1    0x02
salt     16    container-key salt
ss_header 24   secretstream header (from init_push)
chunks   ...   secretstream chunks
```

- Container key = `derive_key(MEK, salt, b"tessera/container/v1")`.
- Payload is a **streamed tar** (POSIX ustar) of the source, `arcname` =
  the source's basename, split into **CHUNK = 65536-byte** plaintext pieces.
- Each non-final chunk: `secretstream_push(plaintext_chunk, ad, TAG_MESSAGE)`,
  exactly `CHUNK + 17` bytes on disk. The final chunk uses `TAG_FINAL` and is
  `≤ CHUNK + 17` bytes.
- **AAD:** the first chunk (and only the first) is pushed with
  `ad = magic || version || salt` (the 21-byte header); all later chunks use
  `ad = b""`.
- Decryption reads `CHUNK + 17` bytes per pull; a short read is the final
  chunk. A missing `TAG_FINAL` (EOF first) is a truncation error. Extraction
  must use a safe filter equivalent to tarfile's `data` (reject absolute
  paths, `..`, symlink/hardlink escapes, and device/special files).

## 9. Conformance

Regenerate vectors with `python -m tessera.tools.gen_kat`. A port passes when
it reproduces, from `kat.json`:

1. `argon2id` — start here; the hardest to match. Confirms Argon2id v1.3 with
   parallelism=1 and your opslimit/memlimit interpretation.
2. `reduce_mod_p`, `field` — big-integer mod-P arithmetic and sign handling.
3. `blake2b_kdf`, `xchacha20poly1305`, `secretstream_decrypt` — primitives.
4. `aad` — exact byte layout of §6.
5. `string_normalization` — ExactStringProcessor canonicalization (§3a),
   including NFC composition, Python whitespace strip, and full casefold.
6. `vault_unlock` — full integration: unlock the provided state to `mek_hex`.
7. `vault_unlock_unicode` — integration with non-ASCII answers; both
   `answers` and `alt_answers` (decomposed/case variants) must unlock.
8. `vault_unlock_single_field` — the M=1/t=1 degenerate case. With one field
   and threshold 1 the polynomial is degree 0 and tessera **is** a plain
   password vault (password → Argon2id → unblind → KEK → AEAD); this is a
   supported configuration on the same code path, and ports must handle it.
```
