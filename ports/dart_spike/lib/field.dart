// Pure-Dart GF(P) arithmetic for the tessera spike — the one piece that is NOT
// a libsodium call and must be reimplemented per language.
//
// Dart's BigInt has modPow/modInverse and its `%` is non-negative for a
// positive modulus (like Python), so the JS-style `((v % P) + P) % P`
// normalization is not strictly required here — but we keep results reduced
// into [0, P) explicitly to mirror the spec and stay robust.

import 'dart:typed_data';

final BigInt P = (BigInt.one << 256) - BigInt.from(189);

BigInt _mod(BigInt v) {
  final r = v % P;
  return r.isNegative ? r + P : r;
}

/// Reduce a big-endian byte string mod P.
BigInt reduceModP(Uint8List bytes) {
  var v = BigInt.zero;
  for (final b in bytes) {
    v = (v << 8) | BigInt.from(b);
  }
  return _mod(v);
}

/// Horner evaluation of a polynomial mod P. coeffs[0] is the constant term.
BigInt polyEval(List<BigInt> coeffs, BigInt x) {
  var result = BigInt.zero;
  for (var i = coeffs.length - 1; i >= 0; i--) {
    result = _mod(result * x + coeffs[i]);
  }
  return result;
}

/// Lagrange interpolation at x=0 over GF(P).
BigInt lagrangeInterpolateAtZero(List<(BigInt, BigInt)> points) {
  var secret = BigInt.zero;
  for (var i = 0; i < points.length; i++) {
    final (xi, yi) = points[i];
    var num = BigInt.one;
    var den = BigInt.one;
    for (var j = 0; j < points.length; j++) {
      if (j == i) continue;
      final xj = points[j].$1;
      num = _mod(num * (-xj));
      den = _mod(den * (xi - xj));
    }
    final term = _mod(yi * num * den.modInverse(P));
    secret = _mod(secret + term);
  }
  return secret;
}
