"""RuleTarget represents destination for rules."""

from typing import Protocol

from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule
from net_configurator.rules_source import ReaderInterface
from net_configurator.rules_source import RulesSource


class ReaderWriterInterface(ReaderInterface):
    """Interface with methods for reading and writing."""

    def add_rule(self, rule: Rule) -> None:
        """add_rule stub."""
        ...  # noqa: PIE790

    def delete_rule(self, rule_identifier: str) -> None:
        """delete_rule stub."""
        ...  # noqa: PIE790

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """add_filter stub."""
        ...  # noqa: PIE790

    def delete_filter(self, filter_identifier: str) -> None:
        """delete_filter stub."""
        ...  # noqa: PIE790

    def add_owner(self, owner: Owner) -> None:
        """add_owner stub."""
        ...  # noqa: PIE790

    def delete_owner(self, owner_identifier: str) -> None:
        """delete_owner stub."""
        ...  # noqa: PIE790

    def apply_changes(self) -> None:
        """apply_changes stub."""
        ...  # noqa: PIE790


class ReaderWriterFactoryInterface(Protocol):
    """Interface of factory creating ReaderWriter."""

    def create(self) -> ReaderWriterInterface:
        """Create ReaderWriter."""
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
        """Adds rule to target handler.

        Args:
            rule (Rule): Rule to add.

        Raises:
            Exception: Exceptions raised by add_rule of given handler.
        """
        self._handler.add_rule(rule)

    def delete_rule(self, rule_identifier: str) -> None:
        """Deletes rule from target handler.

        Args:
            rule_identifier (str): Identifier of rule to delete.

        Raises:
            Exception: Exceptions raised by delete_rule of given handler.
        """
        self._handler.delete_rule(rule_identifier)

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """Adds packet filter to target handler.

        Args:
            packet_filter (PacketFilter): Packet filter to add.

        Raises:
            Exception: Exceptions raised by add_filter of given handler.
        """
        self._handler.add_filter(packet_filter)

    def delete_filter(self, filter_identifier: str) -> None:
        """Deletes packet filter at target handler.

        Args:
            filter_identifier (str): Identifier of packet filter to delete.

        Raises:
            Exception: Exceptions raised by delete_filter of given handler.
        """
        self._handler.delete_filter(filter_identifier)

    def add_owner(self, owner: Owner) -> None:
        """Adds owner to target handler.

        Args:
            owner (Owner): Owner to add.

        Raises:
            Exception: Exceptions raised by add_owner of given handler.
        """
        self._handler.add_owner(owner)

    def delete_owner(self, owner_identifier: str) -> None:
        """Deletes owner at target handler.

        Args:
            owner_identifier (str): Identifier of owner to delete.

        Raises:
            Exception: Exceptions raised by delete_owner of given handler.
        """
        self._handler.delete_owner(owner_identifier)

    def apply_changes(self) -> None:
        """Applies changes to target handler.

        Raises:
            Exception: Exceptions raised by apply_changes of given handler.
        """
        self._handler.apply_changes()
