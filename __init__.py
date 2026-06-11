"""
tessera — blinded Shamir secret sharing vault.

Public API:
    enroll(mek, answers, processors, threshold, params) -> PublicState
    unlock(state, answers, processors, reliability_order) -> bytes | None

Processors:
    ExactStringProcessor   — for string answers (NFC + casefold normalized)
    RawBytesProcessor      — for raw byte answers
    SecureSketchProcessor  — stub for fuzzy/error-correcting answers

Parameters:
    Argon2Params  — Argon2id configuration
    Params        — full vault parameters (argon2, kdf_context, max_subsets)

State:
    PublicState   — serializable vault state (to_json/from_json, to_bytes/from_bytes)
    FieldEntry    — per-field public data

Errors:
    ThresholdVaultError  — base exception
    InvalidParamsError   — bad parameters
    FieldError           — finite field arithmetic error
    SerializationError   — state serialization failure
"""

from .container import open_container, seal
from .errors import ContainerError, FieldError, InvalidParamsError, SerializationError, ThresholdVaultError
from .params import Argon2Params, Params
from .processor import ExactStringProcessor, FieldProcessor, RawBytesProcessor, SecureSketchProcessor
from .state import FieldEntry, PublicState
from .vault import enroll, unlock

__all__ = [
    "enroll",
    "unlock",
    "seal",
    "open_container",
    "ExactStringProcessor",
    "RawBytesProcessor",
    "SecureSketchProcessor",
    "FieldProcessor",
    "Argon2Params",
    "Params",
    "FieldEntry",
    "PublicState",
    "ThresholdVaultError",
    "InvalidParamsError",
    "FieldError",
    "SerializationError",
    "ContainerError",
]
