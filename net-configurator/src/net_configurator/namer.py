"""Identifier generator."""

import hashlib

from net_configurator.constants import IDENTIFIER_PREFIX


class Namer:
    """Identifier generator."""

    @staticmethod
    def generate_identifier(json_dump: str) -> str:
        """Return identifier for JSON string based on hash.

        Args:
            json_dump (str): String to generate identifier for.

        Returns:
            str: Generated identifier.
        """
        hasher = hashlib.sha1()  # noqa: S324
        hasher.update(json_dump.encode())
        rule_hash = hasher.hexdigest()
        return f'{IDENTIFIER_PREFIX}{rule_hash}'
