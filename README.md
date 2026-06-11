# tessera

A blinded Shamir secret-sharing vault: protect a master encryption key (MEK)
behind **M** personal questions so that any **t** correct answers recover it.

*A* tessera *is a mosaic tile — enough of them and the picture emerges — and
also the Roman army's watchword tablet, the token that carried the daily
password.*

Pure Python plus libsodium (via `pynacl`). The cryptographic core is defined
entirely by libsodium primitives, so this implementation is intended as the
**reference** for planned TypeScript and Dart ports.

## Install

```bash
pip install .                    # library + `tessera` CLI command
pip install -e ".[dev]"          # editable, with pytest for development
pip install -r requirements.txt  # just the runtime dependencies
```

## Use case

Passwords get forgotten; single security answers are weak and guessable.
`tessera` is a *forgiving but brute-force-resistant* key escrow:

- At **enrollment** you provide M answers (e.g. "first pet's name",
  "street you grew up on", a recovery phrase, a hardware token's bytes)
  and a threshold t.
- At **unlock** you answer the questions again. Any t of M correct answers
  recover the MEK — wrong, mistyped, or skipped answers are tolerated as
  long as t are right.
- The vault file contains **only public data** and is safe to store or back
  up anywhere (cloud storage, email, printed QR code). An attacker holding
  the file must still guess t answers, each gated behind Argon2id
  (256 MiB memory-hard hashing by default).

Typical applications: disk-encryption key recovery, password-manager escrow,
digital inheritance ("any 2 of these 4 family secrets"), or backup unlock
for devices.

## How it works

```
enroll:
  S            ← random Shamir secret over GF(P), P = 2^256 − 189
  f(x)         ← random degree-(t−1) polynomial with f(0) = S
  for each answer i (1-based x_i = i):
      w_i      ← processor canonicalization (e.g. NFC + casefold)
      r_i      ← Argon2id(w_i, salt_i)  reduced mod P    (64-byte output)
      c_i      ← (f(x_i) + r_i) mod P                    (blinded share, public)
  KEK          ← BLAKE2b-256(kdf_context || kdf_salt || S)
  ct, tag      ← XChaCha20-Poly1305(KEK, nonce, MEK, AAD = canonical public state)

unlock:
  Phase 1: for each provided answer, recompute r_i′ via Argon2id
           (exactly M hashes, cached — never re-hashed afterwards)
           y_i ← (c_i − r_i′) mod P        (correct answer ⇒ true share)
  Phase 2: for each of the C(M, t) subsets of t points:
           interpolate S′ at x = 0, derive KEK′, attempt AEAD decryption
  The Poly1305 tag is the only correctness oracle. First success returns the
  MEK; exhaustion returns None.
```

Correct answers yield true Shamir shares; wrong answers yield uniformly
wrong field elements that simply fail interpolation. Nothing in the public
state reveals which answers are right.

### Behavior notes

- **Cost**: unlock always performs exactly M Argon2id hashes (a few seconds
  each at default parameters — intentional). Subset enumeration is cheap by
  comparison; `Params.max_subsets` (default 1,000,000) rejects M/t
  combinations that would enumerate too many subsets.
- **Opaque failure**: `unlock` returns `None` with no indication of how many
  or which answers matched.
- **Missing answers**: pass `None` for a question you can't answer; it
  contributes a deterministic wrong share instead of crashing.
- **Tampering**: the entire public state is bound into the AEAD AAD, so
  any modification of the vault file makes unlock fail.
- **`reliability_order`**: optional hint listing field indices most-reliable
  first; subsets of reliable answers are tried first. Affects speed only,
  never correctness.

## Command-line demo

A demonstration CLI ships as `python -m tessera` (run from the
directory *containing* the `tessera/` package) or, equivalently,
`python cli.py` from inside the package directory:

```bash
# Create a vault: prompts for questions, then hidden answers (asked twice),
# generates a random 32-byte MEK and prints it as base64 on stdout
python3 -m tessera enroll --out vault.json --threshold 2

# Recover the MEK: shows stored questions, hidden answer prompts,
# Enter alone skips a question
python3 -m tessera unlock --vault vault.json > mek.b64

# Encrypt a file or folder into a container at enrollment
# (writes secrets.tsra; the MEK is not displayed — the vault recovers it)
python3 -m tessera enroll --encrypt ./secrets --container secrets.tsra

# Answer the questions to decrypt the container
python3 -m tessera unlock --decrypt secrets.tsra --dest ./restored
```

If `--threshold` is omitted, enroll prompts for it interactively. The CLI
requires a majority threshold (t ≥ ⌈M/2⌉): anything lower would let an
attacker target only the few easiest answers. (The library API itself
permits any t in `[1, M]`.)

`enroll --fast` uses weakened Argon2id parameters for quick demos (the
64-byte hash-length invariant is kept; unlock automatically uses whatever
parameters are stored in the vault).

CLI security properties: answers are read with `getpass` (no echo, never in
argv or shell history); stdout carries only the base64 MEK while all prompts
go to stderr; failure is the opaque message `unlock failed` with exit code 1.
`--encrypt` never deletes the original — removing the plaintext is left to
you, deliberately.

## Python API

```python
import tessera as tv

procs = [tv.ExactStringProcessor()] * 3
state = tv.enroll(
    mek=b"\x00" * 32,                       # the key to protect (any length)
    answers=["fluffy", "paris", "honda"],
    processors=procs,
    threshold=2,
)
blob = state.to_json()                       # public; store anywhere

state = tv.PublicState.from_json(blob)
mek = tv.unlock(state, ["fluffy", "WRONG", "honda"], procs)
assert mek == b"\x00" * 32                   # 2 of 3 correct ⇒ success
```

### Functions

#### `enroll(mek, answers, processors, threshold, params=None) -> PublicState`

Create a vault protecting `mek`.

| argument | meaning |
|---|---|
| `mek: bytes` | key to protect; any length |
| `answers: list` | M answers, one per field |
| `processors: list[FieldProcessor]` | M processors, matching `answers` |
| `threshold: int` | t, in `[1, M]` |
| `params: Params \| None` | defaults to `Params()` |

Raises `InvalidParamsError` / `ValueError` on bad input (including
`C(M, t) > params.max_subsets` and `argon2.hash_len < 64`).

#### `unlock(state, answers, processors, reliability_order=None) -> bytes | None`

Recover the MEK. `answers` may contain `None` for skipped questions.
`processors` must match enrollment in type and order.
`reliability_order` is an optional list of 0-based field indices,
most reliable first. Returns the MEK, or `None` on any failure.

### Processors

A `FieldProcessor` converts a raw answer into stable canonical bytes
(the input to Argon2id), plus optional public helper data:

- `enroll(answer) -> (helper: bytes, stable_bytes: bytes)`
- `recover(helper, answer) -> bytes` — must return the same stable bytes
  for an acceptable answer; returns `b""` for `answer=None`.

| class | accepts | normalization |
|---|---|---|
| `ExactStringProcessor` | `str` | Unicode NFC + casefold (case-insensitive) |
| `RawBytesProcessor` | `bytes` | none (exact match) |
| `SecureSketchProcessor` | — | **stub**; raises `NotImplementedError`. Documents the intended LSH + secure-sketch design for fuzzy answers (biometrics, noisy sensors). |

Custom processors implementing the protocol can be passed directly.

### Parameters

```python
# opslimit = Argon2id passes; memlimit = bytes. libsodium fixes parallelism=1.
tv.Argon2Params(opslimit=3, memlimit=256 * 1024 * 1024, hash_len=64)
tv.Params(argon2=Argon2Params(), kdf_context=b"tessera/kek/v1", max_subsets=1_000_000)
```

`hash_len` must stay ≥ 64 (security invariant, see below). Changing
`kdf_context` invalidates all existing vaults. Argon2 parameters are stored in
the vault, so unlock needs no configuration.

### State

`PublicState` holds everything public: per-field entries
(`FieldEntry(x, salt, helper, c)`), `threshold`, `kdf_salt`, `kdf_context`,
`argon2`, `nonce`, `ct`, `tag`. Serialization:
`to_json()/from_json()` and `to_bytes()/from_bytes()`.

### Containers

```python
tv.seal(mek, "secrets/", "secrets.tsra")              # encrypt file or folder
names = tv.open_container(mek, "secrets.tsra", "out/")  # decrypt + extract
```

`seal` streams the source through a tar archive and encrypts it in 64 KiB
chunks with libsodium's **secretstream** (XChaCha20-Poly1305), under a key
`BLAKE2b-256(b"tessera/container/v1" || salt || MEK)` (fresh random salt per
container — the same MEK can seal many). Because both seal and open hold only
~one chunk in memory and the tar is never fully materialized, **containers
can exceed available RAM** and no plaintext touches a temp file.
`open_container` raises `ContainerError` on tampering, truncation, or a wrong
key (tamper vs. wrong-key indistinguishable, by design) — secretstream's
per-chunk chaining and `TAG_FINAL` detect reordering, splicing, and a missing
tail. Extraction uses tarfile's `data` filter, which blocks path traversal and
symlink escapes.

### Errors

`TesseraError` (base) → `InvalidParamsError`, `FieldError`,
`SerializationError`, `ContainerError`. Note that `unlock` never raises to
signal a wrong answer — it returns `None`.

## Security model and invariants

- **Single oracle**: only the XChaCha20-Poly1305 tag determines success. No per-field
  correctness checks exist, so partial knowledge leaks nothing.
- **Blinding uniformity**: `r_i` is derived from ≥ 64 bytes of Argon2id
  output reduced mod the 256-bit prime P, giving bias ≤ 2⁻²⁵⁶; blinded
  shares are indistinguishable from random.
- **Hash-count discipline**: Argon2id runs exactly M times per unlock and is
  never called inside the subset loop, so cost is predictable and the
  memory-hard work cannot be amortized away.
- **Brute-force economics**: an offline attacker must run Argon2id per
  candidate answer per field, then find t correct fields. Total answer
  entropy across any t fields is the real security level — choose questions
  accordingly.

### Caveats

- **Zeroization is best-effort**: secrets passing through Python `int` and
  `str` objects cannot be reliably wiped from memory (documented inline).
- `SecureSketchProcessor` is unimplemented; only exact (normalized) matching
  is available today.
- Low-entropy answers (pet names, cities) are dictionary-attackable even
  with Argon2id; the threshold construction multiplies entropy across
  fields but cannot create it.
- The CLI is demonstration-grade, and the question texts it stores in the
  vault file are not covered by the AEAD AAD (tampering with them cannot
  leak the MEK, but could mislead the user).

## Porting (TypeScript / Dart)

This Python package is the reference. The wire format and crypto constructions
are specified byte-for-byte in [`SPEC.md`](SPEC.md), and conformance is pinned
by known-answer vectors in `tests/vectors/kat.json` (regenerate with
`python -m tessera.tools.gen_kat`). A port is correct when it reproduces every
vector; `tests/test_kat.py` shows exactly how each is consumed. Start with the
`argon2id` vectors — Argon2id parity (especially in Dart) is the hardest part.

## Tests

```bash
python3 -m pytest tessera/tests/ -q
```

70 tests cover the GF(P) arithmetic, vault behavior, streaming containers, and
the KAT vectors.
