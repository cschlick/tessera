"""
Custom exception types for tessera.
"""


class ThresholdVaultError(Exception):
    """Base class for all tessera errors."""


class InvalidParamsError(ThresholdVaultError):
    """Raised when enrollment or unlock parameters are invalid."""


class FieldError(ThresholdVaultError):
    """Raised for arithmetic errors in GF(P)."""


class SerializationError(ThresholdVaultError):
    """Raised when state serialization/deserialization fails."""


class ContainerError(ThresholdVaultError):
    """Raised when an encrypted container is malformed, tampered with,
    or decrypted with the wrong MEK."""
