/// tessera_dart — Dart port of tessera, the blinded Shamir secret-sharing
/// vault. The Python package is the reference implementation; this port is
/// conformance-tested against tests/vectors/kat.json (see SPEC.md).
///
/// All cryptography comes from libsodium via package:sodium. Callers supply
/// an initialized [SodiumSumo]:
///   - Flutter apps: `SodiumSumoInit.init()` from package:sodium_libs
///   - plain Dart:   `SodiumSumoInit.init(() => DynamicLibrary.open(...))`
library;

export 'package:sodium/sodium_sumo.dart' show SodiumSumo;

export 'src/field.dart' show P, reduceModP, polyEval, lagrangeInterpolateAtZero;
export 'src/normalize.dart' show normalizeAnswer, exactStringRecover;
export 'src/params.dart' show Argon2Params, Params;
export 'src/state.dart' show FieldEntry, PublicState, bigIntTo32;
export 'src/vault.dart' show enroll, unlock, combinations;
