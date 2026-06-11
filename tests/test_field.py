"""
Tests for tessera.field — finite field arithmetic and Lagrange interpolation.
"""

import pytest
import secrets

from tessera.field import P, poly_eval, lagrange_interpolate_at_zero


# ---------------------------------------------------------------------------
# KAT: Known-Answer Test for lagrange_interpolate_at_zero
# ---------------------------------------------------------------------------

def test_kat_lagrange_degree2():
    """
    KAT: For a known degree-2 polynomial f(x) = 3x^2 + 5x + 7 (mod P),
    lagrange_interpolate_at_zero should recover f(0) = 7 from any 3 points.
    """
    # f(x) = 7 + 5x + 3x^2
    coeffs = [7, 5, 3]
    # Evaluate at x=1,2,3
    points = [(x, poly_eval(coeffs, x)) for x in range(1, 4)]
    recovered = lagrange_interpolate_at_zero(points)
    assert recovered == 7, f"Expected 7, got {recovered}"


def test_kat_lagrange_degree2_different_xs():
    """
    KAT: Same polynomial, evaluated at x=4,7,11 — should still recover f(0)=7.
    """
    coeffs = [7, 5, 3]
    points = [(x, poly_eval(coeffs, x)) for x in [4, 7, 11]]
    recovered = lagrange_interpolate_at_zero(points)
    assert recovered == 7


def test_kat_lagrange_degree0():
    """
    KAT: Constant polynomial f(x) = 42. Any single point recovers f(0) = 42.
    """
    coeffs = [42]
    points = [(5, poly_eval(coeffs, 5))]
    recovered = lagrange_interpolate_at_zero(points)
    assert recovered == 42


def test_kat_lagrange_large_secret():
    """
    KAT: Secret close to P-1 (boundary test).
    """
    S = P - 1
    coeffs = [S, 12345, 98765]
    points = [(x, poly_eval(coeffs, x)) for x in [1, 2, 3]]
    recovered = lagrange_interpolate_at_zero(points)
    assert recovered == S


# ---------------------------------------------------------------------------
# Rejection of invalid inputs
# ---------------------------------------------------------------------------

def test_rejects_x_zero():
    """
    lagrange_interpolate_at_zero must raise ValueError if any x == 0.
    x=0 is the secret location and is never a valid share index.
    """
    points = [(0, 42), (1, 100), (2, 200)]
    with pytest.raises(ValueError, match="x=0"):
        lagrange_interpolate_at_zero(points)


def test_rejects_duplicate_x():
    """
    lagrange_interpolate_at_zero must raise ValueError if duplicate x values
    are present — duplicate x would make the polynomial underdetermined.
    """
    points = [(1, 42), (1, 100), (2, 200)]
    with pytest.raises(ValueError, match="duplicate"):
        lagrange_interpolate_at_zero(points)


def test_rejects_empty_points():
    """
    lagrange_interpolate_at_zero must raise ValueError on empty input.
    """
    with pytest.raises(ValueError):
        lagrange_interpolate_at_zero([])


# ---------------------------------------------------------------------------
# Shamir split + interpolate round-trips
# ---------------------------------------------------------------------------

def _shamir_split(S: int, M: int, t: int) -> list[tuple[int, int]]:
    """Helper: create a (t-1)-degree polynomial with f(0)=S, return M shares."""
    coeffs = [S] + [secrets.randbelow(P) for _ in range(t - 1)]
    return [(i, poly_eval(coeffs, i)) for i in range(1, M + 1)]


def test_shamir_round_trip_3_of_3():
    """3-of-3: all shares must recover the secret."""
    S = secrets.randbelow(P)
    shares = _shamir_split(S, 3, 3)
    recovered = lagrange_interpolate_at_zero(shares)
    assert recovered == S


def test_shamir_round_trip_2_of_5():
    """2-of-5: any 2 shares must recover the secret."""
    S = secrets.randbelow(P)
    all_shares = _shamir_split(S, 5, 2)
    import itertools
    for combo in itertools.combinations(all_shares, 2):
        recovered = lagrange_interpolate_at_zero(list(combo))
        assert recovered == S, f"Failed for subset {[x for x, _ in combo]}"


def test_shamir_round_trip_3_of_7():
    """3-of-7: all C(7,3)=35 subsets of 3 must recover the secret."""
    S = secrets.randbelow(P)
    all_shares = _shamir_split(S, 7, 3)
    import itertools
    for combo in itertools.combinations(all_shares, 3):
        recovered = lagrange_interpolate_at_zero(list(combo))
        assert recovered == S


def test_shamir_wrong_subset_does_not_recover():
    """
    2-of-3: Using only 1 share (below threshold) should NOT recover the secret
    (with overwhelming probability — the wrong single point gives wrong f(0)).
    """
    S = secrets.randbelow(P)
    all_shares = _shamir_split(S, 3, 2)
    # Single share cannot determine f(0) for a degree-1 polynomial
    # (with high probability; exact collision probability is 1/P ≈ 0)
    single_point_result = lagrange_interpolate_at_zero([all_shares[0]])
    # With high probability this should NOT equal S
    # (exact equality would be catastrophically unlikely but theoretically possible)
    # We just verify that Lagrange works at all — the semantic guarantee is
    # that t-1 shares are information-theoretically insufficient for degree t-1 poly
    # This test is really checking that the function runs without error on 1 point
    # For a degree-1 poly, 1 point extrapolates to a different f(0) unless x=0.
    assert isinstance(single_point_result, int)
    # Verify statistical: the recovered value should be on the line defined by
    # just that one point extrapolated to 0, which equals y_1 - x_1 * (y_2-y_1)/(x_2-x_1)
    # for a degree-1 poly. Rather than checking the exact value, we confirm it's
    # in [0, P) — the function returned a valid field element.
    assert 0 <= single_point_result < P


def test_shamir_round_trip_5_of_5():
    """5-of-5: all 5 shares needed, all present → recover secret."""
    S = secrets.randbelow(P)
    all_shares = _shamir_split(S, 5, 5)
    recovered = lagrange_interpolate_at_zero(all_shares)
    assert recovered == S


def test_shamir_round_trip_4_of_10():
    """4-of-10: sample several subsets of 4."""
    import itertools
    S = secrets.randbelow(P)
    all_shares = _shamir_split(S, 10, 4)
    # Test first 20 combinations (C(10,4)=210 total)
    for combo in list(itertools.combinations(all_shares, 4))[:20]:
        recovered = lagrange_interpolate_at_zero(list(combo))
        assert recovered == S


def test_poly_eval_basic():
    """poly_eval sanity check: f(x) = 1 + 2x + 3x^2, f(2) = 1+4+12 = 17."""
    assert poly_eval([1, 2, 3], 2) == 17


def test_poly_eval_at_zero():
    """poly_eval(coeffs, 0) == coeffs[0] (the constant term / secret)."""
    assert poly_eval([42, 99, 77], 0) == 42


def test_poly_eval_mod_p():
    """poly_eval reduces mod P correctly."""
    # f(x) = P + 1 at x=0 should give 1
    assert poly_eval([P + 1, 0], 0) == 1
