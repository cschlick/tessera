// ExactStringProcessor canonicalization for Dart, matching the Python
// reference byte-for-byte:
//
//     NFC -> strip (Python unicode whitespace) -> casefold -> UTF-8
//
// NFC comes from package:unorm_dart; casefold and the whitespace set are
// GENERATED from the reference CPython (unicode_tables.dart), so full case
// folding (ß -> ss, final sigma, ligature expansion) matches by construction.
// Note: the result is intentionally NOT re-normalized after casefold — the
// reference doesn't either. Parity is pinned by the `string_normalization`
// KAT vectors.

import 'dart:convert';
import 'dart:typed_data';

import 'package:unorm_dart/unorm_dart.dart' as unorm;

import 'unicode_tables.dart';

String _casefold(String s) {
  final b = StringBuffer();
  for (final r in s.runes) {
    b.write(kCasefold[r] ?? String.fromCharCode(r));
  }
  return b.toString();
}

String _stripPy(String s) {
  final runes = s.runes.toList();
  var start = 0;
  var end = runes.length;
  while (start < end && kPyWhitespace.contains(runes[start])) {
    start++;
  }
  while (end > start && kPyWhitespace.contains(runes[end - 1])) {
    end--;
  }
  return String.fromCharCodes(runes.sublist(start, end));
}

String normalizeAnswer(String s) => _casefold(_stripPy(unorm.nfc(s)));

/// ExactStringProcessor.recover: canonical UTF-8 bytes, b"" for missing.
Uint8List exactStringRecover(String? answer) => answer == null
    ? Uint8List(0)
    : Uint8List.fromList(utf8.encode(normalizeAnswer(answer)));
