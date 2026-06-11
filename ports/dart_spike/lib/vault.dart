// Pure-Dart tessera vault logic for the capstone spike: PublicState JSON
// parsing, the canonical AAD encoder (SPEC.md §6), and unlock (SPEC.md §5).
// Crypto primitives come in through the Sodium bindings; everything in this
// file is per-language port surface.

import 'dart:convert';
import 'dart:typed_data';

import 'field.dart';
import 'normalize.dart';
import 'sodium.dart';

class FieldEntry {
  final int x;
  final Uint8List salt;
  final Uint8List helper;
  final BigInt c;
  FieldEntry(this.x, this.salt, this.helper, this.c);
}

class PublicState {
  final List<FieldEntry> fields;
  final int threshold;
  final Uint8List kdfSalt;
  final Uint8List kdfContext;
  final int opslimit;
  final int memlimit;
  final int hashLen;
  final Uint8List nonce;
  final Uint8List ct;
  final Uint8List tag;

  PublicState(this.fields, this.threshold, this.kdfSalt, this.kdfContext,
      this.opslimit, this.memlimit, this.hashLen, this.nonce, this.ct, this.tag);

  static PublicState fromJson(Map<String, dynamic> obj) {
    final fields = (obj['fields'] as List).map((f) {
      final m = f as Map<String, dynamic>;
      return FieldEntry(
        m['x'] as int,
        base64Decode(m['salt'] as String),
        base64Decode(m['helper'] as String),
        BigInt.parse(m['c'] as String), // decimal string, per spec
      );
    }).toList();
    final a = obj['argon2'] as Map<String, dynamic>;
    return PublicState(
      fields,
      obj['threshold'] as int,
      base64Decode(obj['kdf_salt'] as String),
      base64Decode(obj['kdf_context'] as String),
      a['opslimit'] as int,
      a['memlimit'] as int,
      a['hash_len'] as int,
      base64Decode(obj['nonce'] as String),
      base64Decode(obj['ct'] as String),
      base64Decode(obj['tag'] as String),
    );
  }
}

Uint8List _u32(int v) =>
    Uint8List(4)..buffer.asByteData().setUint32(0, v, Endian.big);

Uint8List _u64(int v) =>
    Uint8List(8)..buffer.asByteData().setUint64(0, v, Endian.big);

/// Big-endian, exactly 32 bytes (for P and c_i / S).
Uint8List bigIntTo32(BigInt v) {
  final out = Uint8List(32);
  var x = v;
  for (var i = 31; i >= 0; i--) {
    out[i] = (x & BigInt.from(0xff)).toInt();
    x = x >> 8;
  }
  return out;
}

/// Canonical AAD per SPEC.md §6. Covers everything except ct/tag.
Uint8List computeAad(PublicState s) {
  final b = BytesBuilder();
  b.add(_u32(1)); // state format version
  b.add(bigIntTo32(P));
  b.add(_u32(s.fields.length));
  b.add(_u32(s.threshold));
  for (final fe in s.fields) {
    b.add(_u32(fe.x));
    b.add(_u32(fe.salt.length));
    b.add(fe.salt);
    b.add(_u32(fe.helper.length));
    b.add(fe.helper);
    b.add(bigIntTo32(fe.c));
  }
  b.add(_u32(s.kdfSalt.length));
  b.add(s.kdfSalt);
  b.add(_u32(s.kdfContext.length));
  b.add(s.kdfContext);
  b.add(_u64(s.opslimit));
  b.add(_u64(s.memlimit));
  b.add(_u32(s.hashLen));
  b.add(_u32(s.nonce.length));
  b.add(s.nonce);
  return b.toBytes();
}

// ExactStringProcessor.recover lives in normalize.dart (NFC + Python-exact
// strip/casefold, pinned by the string_normalization KAT vectors).

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

/// Unlock per SPEC.md §5. Returns the MEK or null (opaque failure).
Uint8List? unlock(Sodium sodium, PublicState st, List<String?> answers) {
  if (answers.length != st.fields.length) return null;

  // Phase 1: exactly M Argon2id calls, results cached as candidate points.
  final points = <(BigInt, BigInt)>[];
  for (var i = 0; i < st.fields.length; i++) {
    final fe = st.fields[i];
    final w = exactStringRecover(answers[i]);
    final h = sodium.argon2id(w, fe.salt, st.opslimit, st.memlimit, st.hashLen);
    final r = reduceModP(h);
    var y = (fe.c - r) % P;
    if (y.isNegative) y += P;
    points.add((BigInt.from(fe.x), y));
  }

  // Phase 2: subset enumeration; the AEAD tag is the single oracle.
  final aad = computeAad(st);
  final ctAndTag = Uint8List.fromList([...st.ct, ...st.tag]);
  for (final subset in combinations(points, st.threshold)) {
    final sPrime = lagrangeInterpolateAtZero(subset);
    final kek = sodium.generichash(
        Uint8List.fromList(
            [...st.kdfContext, ...st.kdfSalt, ...bigIntTo32(sPrime)]),
        32);
    final mek = sodium.aeadDecrypt(kek, st.nonce, ctAndTag, aad);
    if (mek != null) return mek;
  }
  return null;
}
