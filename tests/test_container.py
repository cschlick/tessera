"""
Tests for tessera.container — encrypted file/folder containers.
"""

import os

import pytest

from tessera import ContainerError, open_container, seal
from tessera.container import CHUNK


MEK = b"\x42" * 32


def test_file_round_trip(tmp_path):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"hello container")
    container = tmp_path / "c.tsra"
    seal(MEK, str(src), str(container))

    dest = tmp_path / "out"
    names = open_container(MEK, str(container), str(dest))
    assert names == ["secret.txt"]
    assert (dest / "secret.txt").read_bytes() == b"hello container"


def test_folder_round_trip(tmp_path):
    src = tmp_path / "docs"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_bytes(b"alpha")
    (src / "sub" / "b.txt").write_bytes(b"beta")
    container = tmp_path / "c.tsra"
    seal(MEK, str(src), str(container))

    dest = tmp_path / "out"
    names = open_container(MEK, str(container), str(dest))
    assert names == ["docs"]
    assert (dest / "docs" / "a.txt").read_bytes() == b"alpha"
    assert (dest / "docs" / "sub" / "b.txt").read_bytes() == b"beta"


def test_wrong_mek_rejected(tmp_path):
    src = tmp_path / "f"
    src.write_bytes(b"x")
    container = tmp_path / "c.tsra"
    seal(MEK, str(src), str(container))
    with pytest.raises(ContainerError):
        open_container(b"\x00" * 32, str(container), str(tmp_path / "out"))


def test_tamper_rejected(tmp_path):
    src = tmp_path / "f"
    src.write_bytes(b"x" * 100)
    container = tmp_path / "c.tsra"
    seal(MEK, str(src), str(container))
    blob = bytearray(container.read_bytes())
    blob[50] ^= 0x01  # flip one ciphertext bit
    container.write_bytes(bytes(blob))
    with pytest.raises(ContainerError):
        open_container(MEK, str(container), str(tmp_path / "out"))


def test_variable_length_mek(tmp_path):
    # The library allows MEKs of any length; BLAKE2b absorbs them.
    src = tmp_path / "f"
    src.write_bytes(b"x")
    container = tmp_path / "c.tsra"
    seal(b"short", str(src), str(container))
    names = open_container(b"short", str(container), str(tmp_path / "out"))
    assert names == ["f"]


def test_not_a_container(tmp_path):
    bogus = tmp_path / "bogus"
    bogus.write_bytes(b"definitely not a container")
    with pytest.raises(ContainerError):
        open_container(MEK, str(bogus), str(tmp_path / "out"))


def test_missing_source(tmp_path):
    with pytest.raises(ContainerError):
        seal(MEK, str(tmp_path / "nope"), str(tmp_path / "c.tsra"))


def test_nonces_unique_per_seal(tmp_path):
    src = tmp_path / "f"
    src.write_bytes(b"same input")
    c1, c2 = tmp_path / "c1", tmp_path / "c2"
    seal(MEK, str(src), str(c1))
    seal(MEK, str(src), str(c2))
    # Fresh salt + stream header each time: identical plaintext, different bytes.
    assert c1.read_bytes() != c2.read_bytes()
    assert c1.read_bytes()[5:21] != c2.read_bytes()[5:21]  # 16-byte salt differs


def test_large_payload_multichunk_round_trip(tmp_path):
    # Payload several times the chunk size exercises the streaming path
    # (multiple non-final chunks plus a final chunk).
    src = tmp_path / "big"
    src.mkdir()
    blob = os.urandom(CHUNK * 3 + 1234)
    (src / "data.bin").write_bytes(blob)
    container = tmp_path / "c.tsra"
    seal(MEK, str(src), str(container))

    dest = tmp_path / "out"
    names = open_container(MEK, str(container), str(dest))
    assert names == ["big"]
    assert (dest / "big" / "data.bin").read_bytes() == blob


def test_truncation_rejected(tmp_path):
    # Dropping the final chunk must be detected (missing TAG_FINAL).
    src = tmp_path / "big"
    src.mkdir()
    (src / "data.bin").write_bytes(os.urandom(CHUNK * 2 + 500))
    container = tmp_path / "c.tsra"
    seal(MEK, str(src), str(container))
    blob = container.read_bytes()
    container.write_bytes(blob[:-200])  # chop the tail
    with pytest.raises(ContainerError):
        open_container(MEK, str(container), str(tmp_path / "out"))
