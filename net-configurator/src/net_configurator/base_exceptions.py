"""Exceptions used as a base for all other ones."""


class FatalError(Exception):
    """Exception indicating there is no way to recover."""


class RecoverableError(Exception):
    """Exception giving a chance of success if operation retried."""
