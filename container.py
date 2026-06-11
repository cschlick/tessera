"""
Encrypted file/folder containers for tessera (chunked, streaming).

seal():           pack a file or directory into a tar stream and encrypt it
                  with libsodium's secretstream (XChaCha20-Poly1305), one
                  64 KiB chunk at a time.
open_container(): decrypt a container and extract its contents, streaming.

Container format:
    magic     4 bytes    b"TSRA"
    version   1 byte      0x02
    salt     16 bytes     container-key salt
    ss_header 24 bytes    secretstream header (from init_push)
    chunks   ...          sequence of secretstream chunks; every non-final
                          chunk is exactly CHUNK + ABYTES bytes, the final
                          chunk (tagged TAG_FINAL) is <= that.

Why streaming: a folder can easily exceed available RAM. Both seal and open
hold only ~one chunk in memory; the tar archive is never fully materialized,
and no plaintext is ever written to a temporary file.

Security:
- The container key is BLAKE2b-256(domain || salt || MEK) — never the MEK
  directly — so any-length MEKs work and the same MEK can seal many
  containers (fresh salt each time).
- secretstream chains chunks and marks the last with TAG_FINAL, so
  truncation, reordering, and splicing are all detected. A missing final
  chunk is rejected.
- The 21-byte plaintext header (magic|version|salt) is bound as additional
  data on the first chunk, so it cannot be altered undetectably.
- Extraction uses tarfile's "data" filter (path traversal, absolute paths,
  symlink escapes, and special files are rejected).

Porting note: secretstream is a libsodium construction available in every
binding (libsodium.js, Dart sodium, …); CHUNK is the one free parameter and
must match across implementations to read each other's containers.
"""

from __future__ import annotations

import os
import tarfile

from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_state as _SSState,
    crypto_secretstream_xchacha20poly1305_init_push as _ss_init_push,
    crypto_secretstream_xchacha20poly1305_push as _ss_push,
    crypto_secretstream_xchacha20poly1305_init_pull as _ss_init_pull,
    crypto_secretstream_xchacha20poly1305_pull as _ss_pull,
    crypto_secretstream_xchacha20poly1305_ABYTES as _ABYTES,
    crypto_secretstream_xchacha20poly1305_HEADERBYTES as _HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as _TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL as _TAG_FINAL,
)
from nacl.exceptions import CryptoError

from .errors import ContainerError
from .kdf import derive_key

MAGIC = b"TSRA"
VERSION = 2
_CONTAINER_DOMAIN = b"tessera/container/v1"
_HEADER_LEN = 4 + 1 + 16  # magic | version | salt
CHUNK = 64 * 1024  # plaintext bytes per secretstream chunk
_CIPHER_CHUNK = CHUNK + _ABYTES  # exact size of every non-final chunk on disk


def _container_key(mek: bytes, salt: bytes) -> bytes:
    """Derive the 32-byte container key from the MEK (BLAKE2b-256)."""
    return derive_key(mek, salt, _CONTAINER_DOMAIN)


class _SealWriter:
    """
    Writable file-like that tar writes into. Buffers plaintext into CHUNK-sized
    pieces and pushes each through secretstream to the output file. The last
    piece (emitted on close) is tagged TAG_FINAL.
    """

    def __init__(self, state, out, first_ad: bytes):
        self._state = state
        self._out = out
        self._buf = bytearray()
        self._first_ad = first_ad
        self._ad_used = False
        self._closed = False

    def _emit(self, chunk: bytes, final: bool) -> None:
        ad = b"" if self._ad_used else self._first_ad
        self._ad_used = True
        tag = _TAG_FINAL if final else _TAG_MESSAGE
        self._out.write(_ss_push(self._state, bytes(chunk), ad, tag))

    def write(self, data) -> int:
        self._buf += data
        # Emit only when strictly more than a chunk is buffered, so a non-final
        # chunk is always followed by at least one more byte. This guarantees
        # close() always has a (possibly empty) chunk to mark TAG_FINAL.
        while len(self._buf) > CHUNK:
            self._emit(self._buf[:CHUNK], final=False)
            del self._buf[:CHUNK]
        return len(data)

    def flush(self) -> None:  # tarfile may call this
        pass

    def close(self) -> None:
        if self._closed:
            return
        self._emit(self._buf, final=True)
        self._buf = bytearray()
        self._closed = True


class _OpenReader:
    """
    Readable file-like that tar reads from. Pulls and decrypts one secretstream
    chunk at a time, returning plaintext on demand. Raises ContainerError on
    authentication failure or truncation (missing TAG_FINAL).
    """

    def __init__(self, f, state, first_ad: bytes):
        self._f = f
        self._state = state
        self._first_ad = first_ad
        self._ad_used = False
        self._plain = bytearray()
        self._done = False

    def _pull_next(self) -> None:
        # Every non-final chunk is exactly _CIPHER_CHUNK bytes; the final chunk
        # is shorter (read to EOF). Reading _CIPHER_CHUNK aligns on boundaries.
        cipher = self._f.read(_CIPHER_CHUNK)
        if not cipher:
            raise ContainerError("truncated container (missing final chunk)")
        ad = b"" if self._ad_used else self._first_ad
        self._ad_used = True
        try:
            msg, tag = _ss_pull(self._state, cipher, ad)
        except CryptoError as e:
            raise ContainerError(
                "container authentication failed (tampered or wrong key)"
            ) from e
        self._plain += msg
        if tag == _TAG_FINAL:
            self._done = True

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            while not self._done:
                self._pull_next()
            out = bytes(self._plain)
            self._plain = bytearray()
            return out
        while len(self._plain) < n and not self._done:
            self._pull_next()
        out = bytes(self._plain[:n])
        del self._plain[:n]
        return out


def seal(mek: bytes, src_path: str, container_path: str) -> None:
    """
    Encrypt the file or directory at src_path into container_path, streaming.

    Raises ContainerError if src_path does not exist.
    """
    src_path = os.path.abspath(src_path)
    if not os.path.exists(src_path):
        raise ContainerError(f"source path does not exist: {src_path}")

    salt = os.urandom(16)
    header = MAGIC + bytes([VERSION]) + salt

    key_ba = bytearray(_container_key(mek, salt))
    try:
        state = _SSState()
        ss_header = _ss_init_push(state, bytes(key_ba))
    finally:
        key_ba[:] = b"\x00" * len(key_ba)
        del key_ba

    with open(container_path, "wb") as out:
        out.write(header)
        out.write(ss_header)
        writer = _SealWriter(state, out, first_ad=header)
        # mode "w|" = non-seekable streaming tar (no random access needed).
        with tarfile.open(fileobj=writer, mode="w|") as tar:
            tar.add(src_path, arcname=os.path.basename(src_path))
        writer.close()  # emits the TAG_FINAL chunk


def open_container(mek: bytes, container_path: str, dest_dir: str = ".") -> list[str]:
    """
    Decrypt container_path and extract its contents into dest_dir, streaming.

    Returns the list of top-level names extracted.

    Raises ContainerError if the container is malformed, was tampered with,
    truncated, or the MEK is wrong (tamper vs. wrong-key are indistinguishable
    by design — the AEAD tag is the only oracle).
    """
    try:
        f = open(container_path, "rb")
    except OSError as e:
        raise ContainerError(f"cannot read container: {e}") from e

    try:
        header = f.read(_HEADER_LEN)
        if len(header) < _HEADER_LEN or header[:4] != MAGIC:
            raise ContainerError("not a tessera container")
        if header[4] != VERSION:
            raise ContainerError(f"unsupported container version: {header[4]}")
        salt = header[5:_HEADER_LEN]

        ss_header = f.read(_HEADERBYTES)
        if len(ss_header) != _HEADERBYTES:
            raise ContainerError("truncated container (missing stream header)")

        key_ba = bytearray(_container_key(mek, salt))
        try:
            state = _SSState()
            _ss_init_pull(state, ss_header, bytes(key_ba))
        finally:
            key_ba[:] = b"\x00" * len(key_ba)
            del key_ba

        reader = _OpenReader(f, state, first_ad=header)
        os.makedirs(dest_dir, exist_ok=True)
        names: set[str] = set()
        try:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                for member in tar:
                    names.add(member.name.split("/", 1)[0])
                    # "data" filter blocks traversal, symlink escapes, specials.
                    tar.extract(member, dest_dir, filter="data")
        except ContainerError:
            raise
        except tarfile.TarError as e:
            raise ContainerError(f"container payload is not a valid archive: {e}") from e
        return sorted(names)
    finally:
        f.close()
