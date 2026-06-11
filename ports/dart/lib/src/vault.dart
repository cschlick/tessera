/// Core enrollment and unlock logic (mirrors the Python reference vault.py).
///
/// Security invariants (same as the reference):
/// 1. Single oracle: only the XChaCha20-Poly1305 tag checks correctness.
/// 2. Argon2id called exactly M times per unlock (Phase 1), cached, never in
///    the subset loop.
/// 3. c_i = (share_i + r_i) mod P with r_i uniform mod P.
/// 4. r_i derived from >= 64 bytes of Argon2id output.
/// 5. Failure is opaque: return null, no count/index info.
/// 6. Best-effort zeroization: keys live in sodium SecureKey (mlock'd,
///    memzero'd on dispose) where the API allows.
library;

import 'dart:typed_data';

import 'package:sodium/sodium_sumo.dart';

import 'field.dart';
import 'normalize.dart';
import 'params.dart';
import 'state.dart';

/// C(n, k) without overflow surprises for the sizes we allow.
BigInt _comb(int n, int k) {
  if (k < 0 || k > n) return BigInt.zero;
  var r = BigInt.one;
  for (var i = 0; i < k; i++) {
    r = r * BigInt.from(n - i) ~/ BigInt.from(i + 1);
  }
  return r;
}

Iterable<List<T>> combinations<T>(List<T> items, int k) sync* {
  if (k > items.length) return;
  final idx = List<int>.generate(k, (i) => i);
  while (true) {
    yield [for (final i in idx) items[i]];
    var i = k - 1;
    while (i >= 0 && idx[i] == items.length - k + i) i--;
    if (i < 0) return;
    idx[i]++;
    for (var j = i + 1; j < k; j++) {
      idx[j] = idx[j - 1] + 1;
    }
  }
}

/// Uniform random field element in [0, P) by rejection sampling.
BigInt _randomFieldElement(SodiumSumo sodium) {
  while (true) {
    final bytes = sodium.randombytes.buf(32);
    var v = BigInt.zero;
    for (final b in bytes) {
      v = (v << 8) | BigInt.from(b);
    }
    if (v < P) return v; // rejects with probability ~189/2^256
  }
}

Uint8List _argon2id(
    SodiumSumo sodium, Uint8List password, Uint8List salt, PublicState st) {
  final key = sodium.crypto.pwhash(
    outLen: st.hashLen,
    password: Int8List.view(password.buffer, password.offsetInBytes, password.length),
    salt: salt,
    opsLimit: st.opslimit,
    memLimit: st.memlimit,
    alg: CryptoPwhashAlgorithm.argon2id13,
  );
  try {
    return key.extractBytes();
  } finally {
    key.dispose();
  }
}

/// KEK = BLAKE2b-256( kdf_context || kdf_salt || S_as_32_bytes ).
Uint8List _deriveKek(SodiumSumo sodium, BigInt s, PublicState st) =>
    sodium.crypto.genericHash(
      outLen: 32,
      message: Uint8List.fromList(
          [...st.kdfContext, ...st.kdfSalt, ...bigIntTo32(s)]),
    );

/// Enroll a new vault protecting [mek] behind string answers.
///
/// Uses ExactStringProcessor canonicalization for every field (the only
/// processor ported so far). Throws [ArgumentError] on invalid parameters.
PublicState enroll(
  SodiumSumo sodium,
  Uint8List mek,
  List<String> answers,
  int threshold, {
  Params? params,
}) {
  final p = params ?? Params();
  final m = answers.length;
  if (m < 1) throw ArgumentError('at least one answer is required');
  if (threshold < 1 || threshold > m) {
    throw ArgumentError('threshold must be in [1, $m], got $threshold');
  }
  if (_comb(m, threshold) > BigInt.from(p.maxSubsets)) {
    throw ArgumentError(
        'C($m, $threshold) exceeds maxSubsets=${p.maxSubsets}');
  }
  if (p.argon2.hashLen < 64) {
    throw ArgumentError(
        'argon2.hashLen must be >= 64, got ${p.argon2.hashLen}');
  }

  // Shamir secret and degree-(t-1) polynomial.
  final s = _randomFieldElement(sodium);
  final coeffs = [s, for (var i = 1; i < threshold; i++) _randomFieldElement(sodium)];

  final state = PublicState(
    fields: [],
    threshold: threshold,
    kdfSalt: sodium.randombytes.buf(16),
    kdfContext: p.kdfContext,
    opslimit: p.argon2.opslimit,
    memlimit: p.argon2.memlimit,
    hashLen: p.argon2.hashLen,
    nonce: sodium.randombytes.buf(24),
    ct: Uint8List(0),
    tag: Uint8List(0),
  );

  for (var i = 1; i <= m; i++) {
    final w = exactStringRecover(answers[i - 1]);
    final salt = sodium.randombytes.buf(16);
    final r = reduceModP(_argon2id(sodium, w, salt, state));
    final share = polyEval(coeffs, BigInt.from(i));
    final c = (share + r) % P;
    state.fields.add(FieldEntry(i, salt, Uint8List(0), c));
  }

  final kekBytes = _deriveKek(sodium, s, state);
  final kek = SecureKey.fromList(sodium, kekBytes);
  try {
    final aad = state.computeAad();
    final res = sodium.crypto.aeadXChaCha20Poly1305IETF.encryptDetached(
      message: mek,
      nonce: state.nonce,
      key: kek,
      additionalData: aad,
    );
    state.ct = res.cipherText;
    state.tag = res.mac;
  } finally {
    kek.dispose();
    kekBytes.fillRange(0, kekBytes.length, 0);
  }
  return state;
}

/// Unlock per SPEC.md §5. Returns the MEK, or null (opaque failure).
Uint8List? unlock(SodiumSumo sodium, PublicState st, List<String?> answers) {
  if (answers.length != st.fields.length) return null;

  // Phase 1: exactly M Argon2id calls, results cached as candidate points.
  final points = <(BigInt, BigInt)>[];
  for (var i = 0; i < st.fields.length; i++) {
    final fe = st.fields[i];
    final w = exactStringRecover(answers[i]);
    final r = reduceModP(_argon2id(sodium, w, fe.salt, st));
    var y = (fe.c - r) % P;
    if (y.isNegative) y += P;
    points.add((BigInt.from(fe.x), y));
  }

  // Phase 2: subset enumeration; the AEAD tag is the single oracle.
  final aad = st.computeAad();
  for (final subset in combinations(points, st.threshold)) {
    final sPrime = lagrangeInterpolateAtZero(subset);
    final kekBytes = _deriveKek(sodium, sPrime, st);
    final kek = SecureKey.fromList(sodium, kekBytes);
    try {
      return sodium.crypto.aeadXChaCha20Poly1305IETF.decryptDetached(
        cipherText: st.ct,
        mac: st.tag,
        nonce: st.nonce,
        key: kek,
        additionalData: aad,
      );
    } on SodiumException {
      // Wrong subset: continue silently (no information leaked).
    } finally {
      kek.dispose();
      kekBytes.fillRange(0, kekBytes.length, 0);
    }
  }
  return null;
}
