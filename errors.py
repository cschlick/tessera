"""
Custom exception types for tessera.
"""


class TesseraError(Exception):
    """Base class for all tessera errors."""


class InvalidParamsError(TesseraError):
    """Raised when enrollment or unlock parameters are invalid."""


class FieldError(TesseraError):
    """Raised for arithmetic errors in GF(P)."""


class SerializationError(TesseraError):
    """Raised when state serialization/deserialization fails."""


class ContainerError(TesseraError):
    """Raised when an encrypted container is malformed, tampered with,
    or decrypted with the wrong MEK."""
