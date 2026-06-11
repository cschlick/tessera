/// PublicState, canonical AAD encoding, and JSON serialization
/// (mirrors the Python reference state.py; byte layout per SPEC.md §6/§7).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'field.dart';

class FieldEntry {
  final int x;
  final Uint8List salt;
  final Uint8List helper;
  final BigInt c;
  FieldEntry(this.x, this.salt, this.helper, this.c);
}

Uint8List _u32(int v) =>
    Uint8List(4)..buffer.asByteData().setUint32(0, v, Endian.big);

Uint8List _u64(int v) =>
    Uint8List(8)..buffer.asByteData().setUint64(0, v, Endian.big);

/// Big-endian, exactly 32 bytes (for P, c_i, and S).
Uint8List bigIntTo32(BigInt v) {
  final out = Uint8List(32);
  var x = v;
  for (var i = 31; i >= 0; i--) {
    out[i] = (x & BigInt.from(0xff)).toInt();
    x = x >> 8;
  }
  return out;
}

class PublicState {
  static const int formatVersion = 1;

  final List<FieldEntry> fields;
  final int threshold;
  final Uint8List kdfSalt;
  final Uint8List kdfContext;
  final int opslimit;
  final int memlimit;
  final int hashLen;
  final Uint8List nonce;
  Uint8List ct;
  Uint8List tag;

  PublicState({
    required this.fields,
    required this.threshold,
    required this.kdfSalt,
    required this.kdfContext,
    required this.opslimit,
    required this.memlimit,
    required this.hashLen,
    required this.nonce,
    required this.ct,
    required this.tag,
  });

  /// Canonical AAD per SPEC.md §6. Covers everything except ct/tag.
  Uint8List computeAad() {
    final b = BytesBuilder();
    b.add(_u32(formatVersion));
    b.add(bigIntTo32(P));
    b.add(_u32(fields.length));
    b.add(_u32(threshold));
    for (final fe in fields) {
      b.add(_u32(fe.x));
      b.add(_u32(fe.salt.length));
      b.add(fe.salt);
      b.add(_u32(fe.helper.length));
      b.add(fe.helper);
      b.add(bigIntTo32(fe.c));
    }
    b.add(_u32(kdfSalt.length));
    b.add(kdfSalt);
    b.add(_u32(kdfContext.length));
    b.add(kdfContext);
    b.add(_u64(opslimit));
    b.add(_u64(memlimit));
    b.add(_u32(hashLen));
    b.add(_u32(nonce.length));
    b.add(nonce);
    return b.toBytes();
  }

  /// JSON object per SPEC.md §7 (bytes as base64, c as decimal string).
  Map<String, dynamic> toJson() => {
        'version': formatVersion,
        'fields': [
          for (final fe in fields)
            {
              'x': fe.x,
              'salt': base64Encode(fe.salt),
              'helper': base64Encode(fe.helper),
              'c': fe.c.toString(),
            }
        ],
        'threshold': threshold,
        'kdf_salt': base64Encode(kdfSalt),
        'kdf_context': base64Encode(kdfContext),
        'argon2': {
          'opslimit': opslimit,
          'memlimit': memlimit,
          'hash_len': hashLen,
        },
        'nonce': base64Encode(nonce),
        'ct': base64Encode(ct),
        'tag': base64Encode(tag),
      };

  String toJsonString() => jsonEncode(toJson());

  static PublicState fromJson(Map<String, dynamic> obj) {
    final fields = (obj['fields'] as List).map((f) {
      final m = f as Map<String, dynamic>;
      return FieldEntry(
        m['x'] as int,
        base64Decode(m['salt'] as String),
        base64Decode(m['helper'] as String),
        BigInt.parse(m['c'] as String),
      );
    }).toList();
    final a = obj['argon2'] as Map<String, dynamic>;
    return PublicState(
      fields: fields,
      threshold: obj['threshold'] as int,
      kdfSalt: base64Decode(obj['kdf_salt'] as String),
      kdfContext: base64Decode(obj['kdf_context'] as String),
      opslimit: a['opslimit'] as int,
      memlimit: a['memlimit'] as int,
      hashLen: a['hash_len'] as int,
      nonce: base64Decode(obj['nonce'] as String),
      ct: base64Decode(obj['ct'] as String),
      tag: base64Decode(obj['tag'] as String),
    );
  }

  static PublicState fromJsonString(String s) =>
      fromJson(jsonDecode(s) as Map<String, dynamic>);
}
