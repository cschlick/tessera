"""
PublicState, FieldEntry, AAD computation, and serialization for tessera.

PublicState holds all public data needed to unlock the vault. No secret
material (shares, blinding factors, KEK) is stored here.

AAD (Additional Authenticated Data) is a canonical binary encoding of all
public parameters except ct and tag, ensuring that XChaCha20-Poly1305
authentication covers the entire vault configuration.
"""

from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass

from .errors import SerializationError
from .field import P
from .params import Argon2Params, Params

_MAGIC = b"TVSV"
_VERSION = 1


@dataclass
class FieldEntry:
    """
    Public data for one field (question/answer slot).

    x:       Share index (1-based, never 0).
    salt:    16 random bytes used in Argon2id for this field.
    helper:  Processor-specific public data (e.g., b"" for string/bytes).
    c:       Blinded share: c_i = (share_i + r_i) % P.
             Stored as Python int; serialized as decimal string in JSON.
    """

    x: int
    salt: bytes
    helper: bytes
    c: int


@dataclass
class PublicState:
    """
    All public data for a tessera vault.

    fields:      Ordered list of FieldEntry objects (one per answer).
    threshold:   Minimum number of correct answers needed to unlock (t).
    kdf_salt:    16 random bytes for the BLAKE2b KEK derivation.
    kdf_context: BLAKE2b KDF domain separation string.
    argon2:      Argon2id parameters used during enrollment.
    nonce:       24 random bytes for XChaCha20-Poly1305.
    ct:          XChaCha20-Poly1305 ciphertext (MEK encrypted under KEK).
    tag:         Poly1305 authentication tag (16 bytes).
    """

    fields: list[FieldEntry]
    threshold: int
    kdf_salt: bytes
    kdf_context: bytes
    argon2: Argon2Params
    nonce: bytes
    ct: bytes
    tag: bytes

    # ------------------------------------------------------------------
    # AAD encoding
    # ------------------------------------------------------------------

    def compute_aad(self) -> bytes:
        """
        Compute the canonical AAD for XChaCha20-Poly1305.

        Binary, length-prefixed, deterministic. Covers all public parameters
        EXCEPT ct and tag (which are the outputs of encryption, not inputs).
        Changing any field in PublicState — including adding/removing fields,
        changing threshold, reordering, or altering Argon2 params — will
        invalidate the Poly1305 tag, preventing silent corruption or
        parameter-substitution attacks.

        Format:
            [4B BE: version]
            [32B: P as big-endian]
            [4B BE: M (number of fields)]
            [4B BE: t (threshold)]
            for each field in order:
                [4B BE: x_i]
                [4B BE: len(salt_i)] [salt_i]
                [4B BE: len(helper_i)] [helper_i]
                [32B: c_i as big-endian]
            [4B BE: len(kdf_salt)] [kdf_salt]
            [4B BE: len(kdf_context)] [kdf_context]
            [8B BE: argon2_opslimit]
            [8B BE: argon2_memlimit]
            [4B BE: argon2_hash_len]
            [4B BE: len(nonce)] [nonce]
        """
        parts: list[bytes] = []

        parts.append(struct.pack(">I", _VERSION))
        parts.append(P.to_bytes(32, "big"))
        parts.append(struct.pack(">I", len(self.fields)))
        parts.append(struct.pack(">I", self.threshold))

        for fe in self.fields:
            parts.append(struct.pack(">I", fe.x))
            parts.append(struct.pack(">I", len(fe.salt)))
            parts.append(fe.salt)
            parts.append(struct.pack(">I", len(fe.helper)))
            parts.append(fe.helper)
            parts.append(fe.c.to_bytes(32, "big"))

        parts.append(struct.pack(">I", len(self.kdf_salt)))
        parts.append(self.kdf_salt)
        parts.append(struct.pack(">I", len(self.kdf_context)))
        parts.append(self.kdf_context)
        parts.append(struct.pack(">Q", self.argon2.opslimit))
        parts.append(struct.pack(">Q", self.argon2.memlimit))
        parts.append(struct.pack(">I", self.argon2.hash_len))
        parts.append(struct.pack(">I", len(self.nonce)))
        parts.append(self.nonce)

        return b"".join(parts)

    # ------------------------------------------------------------------
    # JSON serialization
    # ------------------------------------------------------------------

    def to_json(self) -> str:
        """
        Serialize PublicState to a JSON string.

        bytes fields → base64-encoded strings.
        Large integers (P, c_i) → decimal strings to avoid JS precision loss.
        Everything else as-is.
        """

        def b64(b: bytes) -> str:
            return base64.b64encode(b).decode("ascii")

        fields_list = []
        for fe in self.fields:
            fields_list.append(
                {
                    "x": fe.x,
                    "salt": b64(fe.salt),
                    "helper": b64(fe.helper),
                    "c": str(fe.c),  # decimal string for big int
                }
            )

        obj = {
            "version": _VERSION,
            "fields": fields_list,
            "threshold": self.threshold,
            "kdf_salt": b64(self.kdf_salt),
            "kdf_context": b64(self.kdf_context),
            "argon2": {
                "opslimit": self.argon2.opslimit,
                "memlimit": self.argon2.memlimit,
                "hash_len": self.argon2.hash_len,
            },
            "nonce": b64(self.nonce),
            "ct": b64(self.ct),
            "tag": b64(self.tag),
        }
        return json.dumps(obj, separators=(",", ":"))

    @classmethod
    def from_json(cls, s: str) -> "PublicState":
        """
        Deserialize PublicState from a JSON string produced by to_json().

        Raises SerializationError on malformed input.
        """
        try:
            obj = json.loads(s)

            def fromb64(v: str) -> bytes:
                return base64.b64decode(v)

            fields = []
            for fe_obj in obj["fields"]:
                fields.append(
                    FieldEntry(
                        x=int(fe_obj["x"]),
                        salt=fromb64(fe_obj["salt"]),
                        helper=fromb64(fe_obj["helper"]),
                        c=int(fe_obj["c"]),  # decimal string → int
                    )
                )

            argon2_obj = obj["argon2"]
            argon2 = Argon2Params(
                opslimit=int(argon2_obj["opslimit"]),
                memlimit=int(argon2_obj["memlimit"]),
                hash_len=int(argon2_obj["hash_len"]),
            )

            return cls(
                fields=fields,
                threshold=int(obj["threshold"]),
                kdf_salt=fromb64(obj["kdf_salt"]),
                kdf_context=fromb64(obj["kdf_context"]),
                argon2=argon2,
                nonce=fromb64(obj["nonce"]),
                ct=fromb64(obj["ct"]),
                tag=fromb64(obj["tag"]),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise SerializationError(f"Failed to deserialize PublicState from JSON: {exc}") from exc

    # ------------------------------------------------------------------
    # Binary (bytes) serialization
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """
        Serialize PublicState to bytes.

        Format:
            [4B magic: b"TVSV"]
            [4B BE: len(json_utf8)]
            [json_utf8]
        """
        json_bytes = self.to_json().encode("utf-8")
        header = _MAGIC + struct.pack(">I", len(json_bytes))
        return header + json_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "PublicState":
        """
        Deserialize PublicState from bytes produced by to_bytes().

        Raises SerializationError on malformed input.
        """
        try:
            if len(data) < 8:
                raise SerializationError("Data too short to contain header")
            magic = data[:4]
            if magic != _MAGIC:
                raise SerializationError(
                    f"Invalid magic bytes: expected {_MAGIC!r}, got {magic!r}"
                )
            (json_len,) = struct.unpack(">I", data[4:8])
            if len(data) < 8 + json_len:
                raise SerializationError(
                    f"Data too short: expected {8 + json_len} bytes, got {len(data)}"
                )
            json_str = data[8 : 8 + json_len].decode("utf-8")
            return cls.from_json(json_str)
        except SerializationError:
            raise
        except Exception as exc:
            raise SerializationError(f"Failed to deserialize PublicState: {exc}") from exc
