"""Functions for redacting sensitive info from logs."""

from typing import Any

SENSITIVE_KEYS = {'password', 'secret', 'passphrase'}


def redact_sensitive_info(config: Any) -> Any:
    """Function for redacting sensitive info from device config."""
    return {k: ('***REDACTED***' if k.lower() in SENSITIVE_KEYS else v) for k, v in config.items()}
