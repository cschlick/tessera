"""
XChaCha20-Poly1305 (IETF) authenticated encryption for tessera.

Used to wrap the small MEK in the vault. The container (large payloads) uses
the chunked secretstream construction in container.py instead.

libsodium's crypto_aead_xchacha20poly1305_ietf_encrypt returns
ciphertext || 16-byte Poly1305 tag concatenated. We split the tag off so the
PublicState can store ct and tag separately (matching its existing shape).

Porting note: XChaCha20-Poly1305 uses a 24-byte nonce (vs AES-GCM's 12). The
larger nonce is why random nonces are safe here without a counter.
"""

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)
from nacl.exceptions import CryptoError

NONCE_BYTES = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24
TAG_BYTES = 16


def aead_wrap(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with XChaCha20-Poly1305.

    Returns (ciphertext, tag) where tag is the trailing 16-byte Poly1305 tag.

    Security note: nonce must be unique per (key, message). tessera uses a
    fresh 24-byte random nonce, whose size makes random selection safe.
    """
    ct_and_tag = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    ct = ct_and_tag[:-TAG_BYTES]
    tag = ct_and_tag[-TAG_BYTES:]
    return ct, tag


def aead_unwrap(
    key: bytes,
    nonce: bytes,
    ct: bytes,
    tag: bytes,
    aad: bytes,
) -> bytes | None:
    """
    Decrypt ciphertext with XChaCha20-Poly1305.

    Returns plaintext on success, or None if authentication fails.

    Security invariant (Single oracle): This is the ONLY correctness check in
    the entire unlock protocol. There is no per-field match check, no per-share
    MAC, no count of correct answers. The Poly1305 tag covers the full
    reconstructed KEK → the full Shamir secret → all t shares simultaneously.
    Returning None instead of raising ensures callers cannot distinguish which
    subset failed vs. producing wrong plaintext.
    """
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ct + tag, aad, nonce, key)
    except CryptoError:
        # Security invariant: failure is opaque — return None, not an exception
        # carrying count/index/which-subset information.
        return None
