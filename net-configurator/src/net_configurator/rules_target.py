"""RuleTarget represents destination for rules."""

from typing import Protocol

from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule
from net_configurator.rules_source import ReaderInterface
from net_configurator.rules_source import RulesSource


class ReaderWriterInterface(Protocol, ReaderInterface):
    """Interface with methods for reading and writing."""

    def add_rule(self, rule: Rule) -> None:
        """add_rule stub."""
        ...

    def delete_rule(self, rule_identifier: str) -> None:
        """delete_rule stub."""
        ...

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """add_filter stub."""
        ...

    def delete_filter(self, filter_identifier: str) -> None:
        """delete_filter stub."""
        ...

    def add_owner(self, owner: Owner) -> None:
        """add_owner stub."""
        ...

    def delete_owner(self, owner_identifier: str) -> None:
        """delete_owner stub."""
        ...

    def apply_changes(self) -> None:
        """apply_changes stub."""
        ...


class RulesTarget(RulesSource[ReaderWriterInterface]):
    """Target for rules to be read and written."""

    def __init__(self, target_handler: ReaderWriterInterface) -> None:
        """Sets target's reader/writer.

        Args:
            target_handler (ReaderWriterInterface): Object used to read from/write to.
        """
        super().__init__(source_handler=target_handler)

    def add_rule(self, rule: Rule) -> None:
        """Adds rule to target writer.

        Args:
            rule (Rule): Rule to add.
        """
        self._handler.add_rule(rule)

    def delete_rule(self, rule_identifier: str) -> None:
        """Deletes rule at target writer.

        Args:
            rule_identifier (str): Identifier of rule to delete.
        """
        self._handler.delete_rule(rule_identifier)

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """Adds packet filter to target writer.

        Args:
            packet_filter (PacketFilter): Packet filter to add.
        """
        self._handler.add_filter(packet_filter)

    def delete_filter(self, filter_identifier: str) -> None:
        """Deletes packet filter at target writer.

        Args:
            filter_identifier (str): Identifier of packet filter to delete.
        """
        self._handler.delete_filter(filter_identifier)

    def add_owner(self, owner: Owner) -> None:
        """Adds owner to target writer.

        Args:
            owner (Owner): Owner to add.
        """
        self._handler.add_owner(owner)

    def delete_owner(self, owner_identifier: str) -> None:
        """Deletes owner at target writer.

        Args:
            owner_identifier (str): Identifier of owner to delete.
        """
        self._handler.delete_owner(owner_identifier)

    def apply_changes(self) -> None:
        """Applies changes to target writer.

        Raises:
            Exception: Exceptions raised by apply_changes of given target writer.
        """
        self._handler.apply_changes()
