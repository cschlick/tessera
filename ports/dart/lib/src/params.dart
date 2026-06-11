/// Parameter types for tessera (mirrors the Python reference params.py).
library;

import 'dart:convert';
import 'dart:typed_data';

/// Argon2id parameters (libsodium crypto_pwhash; parallelism is fixed at 1).
class Argon2Params {
  /// Passes over memory.
  final int opslimit;

  /// Memory in BYTES.
  final int memlimit;

  /// Output length; security invariant: MUST be >= 64 (bias mod P <= 2^-256).
  final int hashLen;

  const Argon2Params({
    this.opslimit = 3,
    this.memlimit = 256 * 1024 * 1024,
    this.hashLen = 64,
  });
}

/// Full enrollment/unlock parameter set.
class Params {
  final Argon2Params argon2;

  /// BLAKE2b KDF domain separation. Changing it invalidates existing vaults.
  final Uint8List kdfContext;

  /// Upper bound on C(M, t) subset iterations at unlock.
  final int maxSubsets;

  Params({
    this.argon2 = const Argon2Params(),
    Uint8List? kdfContext,
    this.maxSubsets = 1000000,
  }) : kdfContext = kdfContext ?? defaultKdfContext();

  static Uint8List defaultKdfContext() =>
      Uint8List.fromList(utf8.encode('tessera/kek/v1'));
}
