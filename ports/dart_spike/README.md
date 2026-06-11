# tessera Dart spike

A throwaway-but-kept spike proving the planned Dart port can reproduce the
Python reference's cryptography. It validates Dart against the reference
known-answer vectors in `../../tests/vectors/kat.json`.

Strategy: **FFI to the system libsodium** for all crypto primitives (the same
C code the Python reference calls, so parity is by construction and the result
is interoperable), plus **pure-Dart `BigInt`** for the GF(P) field math (the
only piece that genuinely must be reimplemented per language).

## Run

```bash
export PATH="$HOME/dart-sdk/bin:$PATH"   # wherever the SDK lives
dart pub get                              # no third-party deps; no network
dart run bin/kat.dart                     # or: dart run bin/kat.dart /path/to/kat.json
```

## Coverage

| KAT section | Backed by | Status |
|---|---|---|
| `argon2id` | FFI `crypto_pwhash` (Argon2id v1.3, parallelism=1) | ✅ |
| `reduce_mod_p` | pure-Dart bytes → `BigInt` mod P | ✅ |
| `blake2b_kdf` | FFI `crypto_generichash` over `domain‖salt‖secret` | ✅ |
| `xchacha20poly1305` | FFI aead encrypt (ct/tag) | ✅ |
| `field` | pure-Dart `poly_eval` + `lagrange_interpolate_at_zero` | ✅ |
| `secretstream_decrypt` | FFI `init_pull` + `pull` | ✅ |
| `aad` | pure-Dart canonical encoder (SPEC §6) | ✅ |
| `vault_unlock` | full integration (state JSON → Argon2 → subsets → Lagrange → KEK → AEAD → MEK), incl. wrong/missing/below-threshold cases | ✅ |
| `vault_unlock_single_field` | M=1/t=1 degenerate case (plain password vault, same code path) | ✅ |
| `string_normalization` | NFC (`unorm_dart`) + CPython-generated strip/casefold tables | ✅ |
| `vault_unlock_unicode` | non-ASCII answers through the full unlock (decomposed é, STRASSE) | ✅ |

## Notes / caveats

- **No `package:ffi`**: native buffers are allocated via libsodium's own
  `sodium_malloc`/`sodium_free`, so `dart pub get` needs no network.
- The libsodium path is hardcoded (miniforge `libsodium.so.26`, with
  `libsodium.so` fallbacks). A real port must resolve/bundle libsodium
  per-platform — on mobile that means shipping the native lib (Android `.so`,
  iOS xcframework). **FFI parity is proven; native-lib distribution is the
  remaining unknown.**
- **ExactStringProcessor normalization is fully implemented**
  (`lib/normalize.dart`): NFC via `unorm_dart`, plus strip/casefold tables
  generated from the reference CPython (`tessera/tools/gen_dart_unicode.py`
  → `lib/unicode_tables.dart`, Unicode 15.1). Caveat: `unorm_dart`'s NFC
  tables may lag CPython's Unicode version for very new code points; the
  KAT vectors are the arbiter — extend them if exotic scripts matter.
- This is a `ports/` spike, not part of the Python package or its tests.
