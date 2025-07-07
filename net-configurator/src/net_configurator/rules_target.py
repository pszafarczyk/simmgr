"""RuleTarget represents destination for rules."""

from typing import Protocol

from net_configurator.rule import Rule


class WriterInterface(Protocol):
    """Interface with methods for changing rules."""

    def add_rule(self, rule: Rule) -> None:
        """add_rule stub."""
        ...

    def delete_rule(self, rule_identifier: str) -> None:
        """delete_rule stub."""
        ...

    def apply_changes(self) -> None:
        """apply_changes stub."""
        ...
