"""
Finite field arithmetic over GF(P) where P = 2**256 - 189.

P is a confirmed 256-bit prime.
"""

from .errors import FieldError

# Security invariant: P must be ≥256 bits so that r_i (64-byte Argon2id output
# reduced mod P) has bias ≤ 2^-256, making the blinded share c_i
# computationally indistinguishable from random.
P: int = 2**256 - 189


def poly_eval(coeffs: list[int], x: int, p: int = P) -> int:
    """
    Evaluate polynomial with given coefficients at x (mod p).

    coeffs[0] is the constant term (secret S), coeffs[-1] is highest degree.
    Uses Horner's method.
    """
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % p
    return result


def lagrange_interpolate_at_zero(points: list[tuple[int, int]], p: int = P) -> int:
    """
    Lagrange interpolation at x=0 over GF(p).

    Given a list of (x_i, y_i) pairs, recover f(0) where f is the unique
    polynomial of degree < len(points) passing through all points.

    Formula:
        S' = sum_j( y_j * prod_{m≠j}(-x_m) * modinv(prod_{m≠j}(x_j - x_m), P) ) mod P

    Uses Fermat's little theorem for modular inverse: modinv(a, p) = pow(a, p-2, p).

    Raises:
        ValueError: if any x value is 0, or if duplicate x values are present.
    """
    if not points:
        raise ValueError("points list must not be empty")

    xs = [pt[0] for pt in points]

    # Security invariant: reject x=0 because that is the secret location.
    if any(x == 0 for x in xs):
        raise ValueError("x=0 is reserved for the secret; not allowed as a share index")

    # Security invariant: duplicate x values would allow trivial polynomial
    # manipulation attacks.
    if len(xs) != len(set(xs)):
        raise ValueError("duplicate x values are not allowed")

    result = 0
    k = len(points)
    for j in range(k):
        x_j, y_j = points[j]
        # Numerator: prod_{m≠j}(-x_m) mod p
        num = 1
        for m in range(k):
            if m != j:
                num = (num * (-xs[m])) % p
        # Denominator: prod_{m≠j}(x_j - x_m) mod p
        den = 1
        for m in range(k):
            if m != j:
                den = (den * (x_j - xs[m])) % p
        # modinv via Fermat's little theorem (p is prime)
        den_inv = pow(den, p - 2, p)
        result = (result + y_j * num % p * den_inv) % p

    return result
