"""Name generator."""

import hashlib

from net_configurator.constants import NAME_PREFIX


class Namer:
    """Name generator."""

    @staticmethod
    def generate_name(json_dump: str) -> str:
        """Return name for JSON string based on hash.

        Args:
            json_dump (str): String to generate name for.

        Returns:
            str: Generated name.
        """
        hasher = hashlib.sha1()  # noqa: S324
        hasher.update(json_dump.encode())
        rule_hash = hasher.hexdigest()
        return f'{NAME_PREFIX}{rule_hash}'
