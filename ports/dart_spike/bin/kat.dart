// Primitive-level parity spike for the planned Dart port of tessera.
//
// Checks the Dart implementation (libsodium via FFI + pure-Dart field math)
// against the reference vectors in tests/vectors/kat.json, section by section:
//
//   argon2id            FFI  crypto_pwhash (Argon2id v1.3, parallelism=1)
//   reduce_mod_p        Dart big-endian bytes mod P
//   blake2b_kdf         FFI  crypto_generichash over (domain||salt||secret)
//   xchacha20poly1305   FFI  aead encrypt (ct/tag) + decrypt round-trip
//   field               Dart poly_eval + lagrange_interpolate_at_zero
//   secretstream_decrypt FFI init_pull + pull, verifying plaintext and tags
//   aad                 Dart canonical AAD encoder (SPEC.md §6)
//   vault_unlock        full integration: state JSON -> Argon2 -> subsets ->
//                       Lagrange -> KEK -> AEAD decrypt -> MEK
//
// Run from this directory:  dart run bin/kat.dart   [path/to/kat.json]

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../lib/sodium.dart';
import '../lib/field.dart';
import '../lib/normalize.dart';
import '../lib/vault.dart';

int _pass = 0;
int _fail = 0;

void _check(String label, bool ok, {String? want, String? got}) {
  print('  ${ok ? "OK  " : "FAIL"} $label');
  if (!ok && want != null) {
    print('       want $want');
    print('       got  $got');
  }
  ok ? _pass++ : _fail++;
}

void main(List<String> args) {
  final katPath = args.isNotEmpty ? args[0] : '../../tests/vectors/kat.json';
  final f = File(katPath);
  if (!f.existsSync()) {
    stderr.writeln('kat.json not found at $katPath');
    exit(2);
  }
  final kat = jsonDecode(f.readAsStringSync()) as Map<String, dynamic>;
  final s = Sodium.open();
  print('libsodium loaded; ARGON2ID13=${s.argon2id13} '
      'ssStateBytes=${s.ssStateBytes} ssTagFinal=${s.ssTagFinal}\n');

  // --- argon2id ---
  print('argon2id:');
  for (final c in (kat['argon2id'] as List).cast<Map<String, dynamic>>()) {
    final out = s.argon2id(hexDecode(c['password_hex']), hexDecode(c['salt_hex']),
        c['opslimit'], c['memlimit'], c['hash_len']);
    _check('ops=${c['opslimit']} mem=${c['memlimit']}',
        hexEncode(out) == c['output_hex'],
        want: c['output_hex'], got: hexEncode(out));
  }

  // --- reduce_mod_p ---
  print('reduce_mod_p:');
  for (final c in (kat['reduce_mod_p'] as List).cast<Map<String, dynamic>>()) {
    final got = reduceModP(hexDecode(c['input_hex'])).toString();
    _check('input ${c['input_hex'].substring(0, 8)}…',
        got == c['output_decimal'], want: c['output_decimal'], got: got);
  }

  // --- blake2b_kdf ---
  print('blake2b_kdf:');
  for (final c in (kat['blake2b_kdf'] as List).cast<Map<String, dynamic>>()) {
    final msg = Uint8List.fromList([
      ...hexDecode(c['domain_hex']),
      ...hexDecode(c['salt_hex']),
      ...hexDecode(c['secret_hex']),
    ]);
    final key = s.generichash(msg, 32);
    _check('domain ${utf8.decode(hexDecode(c['domain_hex']))}',
        hexEncode(key) == c['key_hex'], want: c['key_hex'], got: hexEncode(key));
  }

  // --- xchacha20poly1305 ---
  print('xchacha20poly1305:');
  for (final c in (kat['xchacha20poly1305'] as List).cast<Map<String, dynamic>>()) {
    final key = hexDecode(c['key_hex']);
    final nonce = hexDecode(c['nonce_hex']);
    final pt = hexDecode(c['plaintext_hex']);
    final ad = hexDecode(c['aad_hex']);
    final ctTag = s.aeadEncrypt(key, nonce, pt, ad);
    final ct = ctTag.sublist(0, ctTag.length - 16);
    final tag = ctTag.sublist(ctTag.length - 16);
    _check('ciphertext', hexEncode(ct) == c['ciphertext_hex'],
        want: c['ciphertext_hex'], got: hexEncode(ct));
    _check('tag', hexEncode(tag) == c['tag_hex'],
        want: c['tag_hex'], got: hexEncode(tag));
  }

  // --- field ---
  print('field:');
  final fld = kat['field'] as Map<String, dynamic>;
  _check('P', P.toString() == fld['P_decimal']);
  final coeffs = (fld['poly_eval']['coeffs_decimal'] as List)
      .map((e) => BigInt.parse(e as String))
      .toList();
  for (final pt in (fld['poly_eval']['points'] as List)) {
    final got = polyEval(coeffs, BigInt.from(pt['x'] as int)).toString();
    _check('poly_eval(x=${pt['x']})', got == pt['result_decimal'],
        want: pt['result_decimal'] as String, got: got);
  }
  final pts = (fld['lagrange_interpolate_at_zero']['points'] as List)
      .map((p) => (BigInt.from((p as List)[0] as int), BigInt.parse(p[1] as String)))
      .toList();
  final secret = lagrangeInterpolateAtZero(pts).toString();
  _check('lagrange@0',
      secret == fld['lagrange_interpolate_at_zero']['secret_decimal'],
      want: fld['lagrange_interpolate_at_zero']['secret_decimal'] as String,
      got: secret);

  // --- secretstream_decrypt ---
  print('secretstream_decrypt:');
  final ss = kat['secretstream_decrypt'] as Map<String, dynamic>;
  final state =
      s.secretstreamInitPull(hexDecode(ss['header_hex']), hexDecode(ss['key_hex']));
  try {
    final chunks = (ss['chunks'] as List).cast<Map<String, dynamic>>();
    for (var i = 0; i < chunks.length; i++) {
      final ch = chunks[i];
      final (msg, tag) =
          s.secretstreamPull(state, hexDecode(ch['ciphertext_hex']), hexDecode(ch['ad_hex']));
      final isFinal = tag == s.ssTagFinal;
      _check('chunk ${i + 1} plaintext', hexEncode(msg) == ch['plaintext_hex'],
          want: ch['plaintext_hex'], got: hexEncode(msg));
      _check('chunk ${i + 1} tag', isFinal == (ch['tag'] == 'FINAL'));
    }
  } finally {
    s.free(state);
  }

  // --- aad ---
  print('aad:');
  final aadVec = kat['aad'] as Map<String, dynamic>;
  final aadState =
      PublicState.fromJson(aadVec['state_json'] as Map<String, dynamic>);
  final aadGot = hexEncode(computeAad(aadState));
  _check('canonical encoding (${(aadVec['aad_hex'] as String).length ~/ 2} bytes)',
      aadGot == aadVec['aad_hex'],
      want: (aadVec['aad_hex'] as String).substring(0, 32),
      got: aadGot.substring(0, 32));

  // --- vault_unlock (capstone) ---
  print('vault_unlock:');
  final vu = kat['vault_unlock'] as Map<String, dynamic>;
  final vuState =
      PublicState.fromJson(vu['state_json'] as Map<String, dynamic>);
  final vuAnswers = (vu['answers'] as List).cast<String>();

  // all answers correct
  var mek = unlock(s, vuState, vuAnswers);
  _check('all answers correct', mek != null && hexEncode(mek) == vu['mek_hex'],
      want: vu['mek_hex'] as String, got: mek == null ? 'null' : hexEncode(mek));

  // one wrong (t=2 of 3 still met) — mirrors the Python KAT test
  final oneWrong = List<String?>.from(vuAnswers)..[1] = 'WRONG';
  mek = unlock(s, vuState, oneWrong);
  _check('one wrong answer', mek != null && hexEncode(mek) == vu['mek_hex'],
      want: vu['mek_hex'] as String, got: mek == null ? 'null' : hexEncode(mek));

  // one missing (null) — must still unlock
  final oneMissing = List<String?>.from(vuAnswers)..[0] = null;
  mek = unlock(s, vuState, oneMissing);
  _check('one missing answer', mek != null && hexEncode(mek) == vu['mek_hex'],
      want: vu['mek_hex'] as String, got: mek == null ? 'null' : hexEncode(mek));

  // below threshold — opaque failure
  mek = unlock(s, vuState, [vuAnswers[0], 'WRONG', null]);
  _check('below threshold -> null', mek == null);

  // --- string_normalization (NFC + Python strip/casefold) ---
  print('string_normalization:');
  final normCases =
      (kat['string_normalization'] as List).cast<Map<String, dynamic>>();
  for (var i = 0; i < normCases.length; i++) {
    final c = normCases[i];
    final input = utf8.decode(hexDecode(c['input_utf8_hex']));
    final got = hexEncode(exactStringRecover(input));
    _check('case ${i + 1} (${input.length > 12 ? input.substring(0, 12) : input})',
        got == c['normalized_utf8_hex'],
        want: c['normalized_utf8_hex'] as String, got: got);
  }

  // --- vault_unlock_unicode (normalization feeding Argon2id) ---
  print('vault_unlock_unicode:');
  final vuu = kat['vault_unlock_unicode'] as Map<String, dynamic>;
  final vuuState =
      PublicState.fromJson(vuu['state_json'] as Map<String, dynamic>);
  mek = unlock(s, vuuState, (vuu['answers'] as List).cast<String>());
  _check('canonical answers', mek != null && hexEncode(mek) == vuu['mek_hex'],
      want: vuu['mek_hex'] as String, got: mek == null ? 'null' : hexEncode(mek));
  mek = unlock(s, vuuState, (vuu['alt_answers'] as List).cast<String>());
  _check('alt forms (decomposed é, STRASSE)',
      mek != null && hexEncode(mek) == vuu['mek_hex'],
      want: vuu['mek_hex'] as String, got: mek == null ? 'null' : hexEncode(mek));

  // --- vault_unlock_single_field (M=1/t=1: plain password vault) ---
  print('vault_unlock_single_field:');
  final v1 = kat['vault_unlock_single_field'] as Map<String, dynamic>;
  final v1State =
      PublicState.fromJson(v1['state_json'] as Map<String, dynamic>);
  final password = (v1['answers'] as List).cast<String>();
  mek = unlock(s, v1State, password);
  _check('correct password', mek != null && hexEncode(mek) == v1['mek_hex'],
      want: v1['mek_hex'] as String, got: mek == null ? 'null' : hexEncode(mek));
  mek = unlock(s, v1State, ['WRONG']);
  _check('wrong password -> null', mek == null);

  print('\n=== $_pass passed, $_fail failed ===');
  exit(_fail == 0 ? 0 : 1);
}
