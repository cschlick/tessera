# tessera_dart

Dart port of [tessera](../../README.md) — blinded Shamir secret-sharing vault.
The Python package is the reference; this port is conformance-tested against
`tests/vectors/kat.json` per [SPEC.md](../../SPEC.md).

All crypto comes from libsodium via `package:sodium` (sumo API — `pwhash`
lives there). Callers supply an initialized `SodiumSumo`:

```dart
// Flutter app (bundled binaries for Android/iOS/desktop/web):
//   pubspec: sodium_libs
final sodium = await SodiumSumoInit.init();

// Plain Dart (tests, CLI): point at a local libsodium
final sodium = await SodiumSumoInit.init(
    () => DynamicLibrary.open('libsodium.so'));
```

## Usage

```dart
import 'package:tessera_dart/tessera_dart.dart';

final state = enroll(sodium, mek, ['fluffy', 'paris', 'honda'], 2);
final json = state.toJsonString();            // public; store anywhere

final restored = PublicState.fromJsonString(json);
final mek2 = unlock(sodium, restored, ['fluffy', null, 'honda']); // 2 of 3
```

Vaults are wire-compatible with the Python reference in both directions
(verified: Dart-enrolled vault unlocked by Python).

## Status

| Area | Status |
|---|---|
| field math, normalization, AAD, state JSON | ✅ ported + KAT-conformant |
| unlock | ✅ all KAT vectors incl. unicode + M=1 |
| enroll (write side) | ✅ round-trip + Python-interop tested |
| containers (secretstream) | ⬜ not yet ported |
| processors beyond ExactString | ⬜ not yet ported |
| isolate wrapper for Flutter UI | ⬜ Argon2id blocks; run unlock/enroll in an isolate |

## Tests

```bash
dart test                       # headless; loads libsodium from
TESSERA_LIBSODIUM=/path/to/libsodium.so dart test   # ...or override
```

`lib/src/unicode_tables.dart` is GENERATED from the reference CPython:
`python -m tessera.tools.gen_dart_unicode` (regenerate when the reference
Python/Unicode version changes).
