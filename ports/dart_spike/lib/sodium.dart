// Minimal libsodium FFI bindings for the tessera Dart spike.
//
// Native memory is allocated through libsodium's own sodium_malloc/sodium_free,
// so this spike needs no `package:ffi` and no network during `dart pub get`.

import 'dart:ffi';
import 'dart:typed_data';

// ---- native signatures ----
typedef _IntFnN = Int32 Function();
typedef _IntFnD = int Function();
typedef _SizeFnN = IntPtr Function();
typedef _SizeFnD = int Function();
typedef _MallocN = Pointer<Uint8> Function(IntPtr);
typedef _MallocD = Pointer<Uint8> Function(int);
typedef _FreeN = Void Function(Pointer<Uint8>);
typedef _FreeD = void Function(Pointer<Uint8>);

typedef _PwhashN = Int32 Function(Pointer<Uint8>, Uint64, Pointer<Uint8>,
    Uint64, Pointer<Uint8>, Uint64, IntPtr, Int32);
typedef _PwhashD = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
    Pointer<Uint8>, int, int, int);

typedef _GenerichashN = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>,
    Uint64, Pointer<Uint8>, IntPtr);
typedef _GenerichashD = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);

typedef _AeadEncN = Int32 Function(
    Pointer<Uint8>, Pointer<Uint64>, Pointer<Uint8>, Uint64, Pointer<Uint8>,
    Uint64, Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _AeadEncD = int Function(Pointer<Uint8>, Pointer<Uint64>,
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>,
    Pointer<Uint8>);

typedef _AeadDecN = Int32 Function(
    Pointer<Uint8>, Pointer<Uint64>, Pointer<Uint8>, Pointer<Uint8>, Uint64,
    Pointer<Uint8>, Uint64, Pointer<Uint8>, Pointer<Uint8>);
typedef _AeadDecD = int Function(Pointer<Uint8>, Pointer<Uint64>,
    Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>,
    Pointer<Uint8>);

typedef _SsInitPullN = Int32 Function(
    Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _SsInitPullD = int Function(
    Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);

typedef _SsPullN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>,
    Pointer<Uint64>, Pointer<Uint8>, Pointer<Uint8>, Uint64, Pointer<Uint8>,
    Uint64);
typedef _SsPullD = int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint64>,
    Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, int);

typedef _U8FnN = Uint8 Function();
typedef _U8FnD = int Function();

class Sodium {
  final DynamicLibrary _lib;
  late final _MallocD _malloc;
  late final _FreeD _free;
  late final _PwhashD _pwhash;
  late final int argon2id13;
  late final _GenerichashD _generichash;
  late final _AeadEncD _aeadEnc;
  late final _AeadDecD _aeadDec;
  late final _SsInitPullD _ssInitPull;
  late final _SsPullD _ssPull;
  late final int ssStateBytes;
  late final int ssTagFinal;

  Sodium._(this._lib) {
    if (_lib.lookupFunction<_IntFnN, _IntFnD>('sodium_init')() < 0) {
      throw StateError('sodium_init failed');
    }
    _malloc = _lib.lookupFunction<_MallocN, _MallocD>('sodium_malloc');
    _free = _lib.lookupFunction<_FreeN, _FreeD>('sodium_free');
    _pwhash = _lib.lookupFunction<_PwhashN, _PwhashD>('crypto_pwhash');
    argon2id13 = _lib
        .lookupFunction<_IntFnN, _IntFnD>('crypto_pwhash_alg_argon2id13')();
    _generichash =
        _lib.lookupFunction<_GenerichashN, _GenerichashD>('crypto_generichash');
    _aeadEnc = _lib.lookupFunction<_AeadEncN, _AeadEncD>(
        'crypto_aead_xchacha20poly1305_ietf_encrypt');
    _aeadDec = _lib.lookupFunction<_AeadDecN, _AeadDecD>(
        'crypto_aead_xchacha20poly1305_ietf_decrypt');
    _ssInitPull = _lib.lookupFunction<_SsInitPullN, _SsInitPullD>(
        'crypto_secretstream_xchacha20poly1305_init_pull');
    _ssPull = _lib.lookupFunction<_SsPullN, _SsPullD>(
        'crypto_secretstream_xchacha20poly1305_pull');
    ssStateBytes = _lib.lookupFunction<_SizeFnN, _SizeFnD>(
        'crypto_secretstream_xchacha20poly1305_statebytes')();
    ssTagFinal = _lib.lookupFunction<_U8FnN, _U8FnD>(
        'crypto_secretstream_xchacha20poly1305_tag_final')();
  }

  static Sodium open() {
    const candidates = [
      '/home/user/software/miniforge3/lib/libsodium.so.26',
      'libsodium.so.26',
      'libsodium.so',
    ];
    for (final c in candidates) {
      try {
        return Sodium._(DynamicLibrary.open(c));
      } catch (_) {/* next */}
    }
    throw StateError('could not locate libsodium (tried: $candidates)');
  }

  // Copy a Dart byte list into a freshly sodium_malloc'd buffer.
  Pointer<Uint8> _buf(List<int> bytes) {
    final p = _malloc(bytes.isEmpty ? 1 : bytes.length);
    if (bytes.isNotEmpty) p.asTypedList(bytes.length).setAll(0, bytes);
    return p;
  }

  Uint8List argon2id(
      Uint8List password, Uint8List salt, int ops, int mem, int hlen) {
    final out = _malloc(hlen);
    final pw = _buf(password);
    final sa = _buf(salt);
    try {
      final rc = _pwhash(out, hlen, pw, password.length, sa, ops, mem, argon2id13);
      if (rc != 0) throw StateError('crypto_pwhash rc=$rc (out of memory?)');
      return Uint8List.fromList(out.asTypedList(hlen));
    } finally {
      _free(out);
      _free(pw);
      _free(sa);
    }
  }

  Uint8List generichash(Uint8List message, int outlen) {
    final out = _malloc(outlen);
    final msg = _buf(message);
    try {
      final rc = _generichash(out, outlen, msg, message.length, nullptr, 0);
      if (rc != 0) throw StateError('crypto_generichash rc=$rc');
      return Uint8List.fromList(out.asTypedList(outlen));
    } finally {
      _free(out);
      _free(msg);
    }
  }

  /// Returns ciphertext||tag (tag = last 16 bytes).
  Uint8List aeadEncrypt(
      Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List ad) {
    final outLen = plaintext.length + 16;
    final out = _malloc(outLen);
    final clen = _malloc(8).cast<Uint64>();
    final m = _buf(plaintext);
    final a = _buf(ad);
    final n = _buf(nonce);
    final k = _buf(key);
    try {
      final rc = _aeadEnc(out, clen, m, plaintext.length, a, ad.length,
          nullptr, n, k);
      if (rc != 0) throw StateError('aead encrypt rc=$rc');
      return Uint8List.fromList(out.asTypedList(clen.value));
    } finally {
      _free(out);
      _free(clen.cast<Uint8>());
      _free(m);
      _free(a);
      _free(n);
      _free(k);
    }
  }

  /// Decrypts ciphertext||tag. Returns plaintext, or null if the tag fails
  /// (single-oracle semantics: callers cannot distinguish why).
  Uint8List? aeadDecrypt(
      Uint8List key, Uint8List nonce, Uint8List ctAndTag, Uint8List ad) {
    if (ctAndTag.length < 16) return null;
    final outLen = ctAndTag.length - 16;
    final out = _malloc(outLen == 0 ? 1 : outLen);
    final mlen = _malloc(8).cast<Uint64>();
    final c = _buf(ctAndTag);
    final a = _buf(ad);
    final n = _buf(nonce);
    final k = _buf(key);
    try {
      final rc = _aeadDec(
          out, mlen, nullptr, c, ctAndTag.length, a, ad.length, n, k);
      if (rc != 0) return null;
      return Uint8List.fromList(out.asTypedList(mlen.value));
    } finally {
      _free(out);
      _free(mlen.cast<Uint8>());
      _free(c);
      _free(a);
      _free(n);
      _free(k);
    }
  }

  /// Allocates and initializes a pull state from header+key.
  Pointer<Uint8> secretstreamInitPull(Uint8List header, Uint8List key) {
    final state = _malloc(ssStateBytes);
    final h = _buf(header);
    final k = _buf(key);
    try {
      final rc = _ssInitPull(state, h, k);
      if (rc != 0) {
        _free(state);
        throw StateError('secretstream init_pull rc=$rc');
      }
      return state;
    } finally {
      _free(h);
      _free(k);
    }
  }

  /// Pulls one chunk. Returns (plaintext, tagByte). Throws on auth failure.
  (Uint8List, int) secretstreamPull(
      Pointer<Uint8> state, Uint8List cipher, Uint8List ad) {
    final mlen = cipher.length; // plaintext <= ciphertext length
    final m = _malloc(mlen == 0 ? 1 : mlen);
    final mlenP = _malloc(8).cast<Uint64>();
    final tagP = _malloc(1);
    final c = _buf(cipher);
    final a = _buf(ad);
    try {
      final rc = _ssPull(state, m, mlenP, tagP, c, cipher.length, a, ad.length);
      if (rc != 0) throw StateError('secretstream pull failed (auth)');
      final outLen = mlenP.value;
      return (Uint8List.fromList(m.asTypedList(outLen)), tagP.value);
    } finally {
      _free(m);
      _free(mlenP.cast<Uint8>());
      _free(tagP);
      _free(c);
      _free(a);
    }
  }

  void free(Pointer<Uint8> p) => _free(p);
}

Uint8List hexDecode(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String hexEncode(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
