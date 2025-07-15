"""Importing rules from external source."""

from types import TracebackType
from typing import Any
from typing import Generic
from typing import Protocol
from typing import TypeVar

from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule


class ReaderInterface(Protocol):
    """Interface with methods for reading."""

    def __enter__(self) -> None:
        """Enter method for context manager."""
        ...

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_tb: TracebackType | None) -> None:
        """Exit method for context manager."""
        ...

    def open(self) -> None:
        """Opens reader."""
        ...

    def close(self) -> None:
        """Closes reader."""
        ...

    def read_all_rules(self) -> list[Any]:
        """read_all_rules stub."""
        ...

    def read_all_filters(self) -> list[Any]:
        """read_all_filters stub."""
        ...

    def read_all_owners(self) -> list[str]:
        """read_all_owners stub."""
        ...


T = TypeVar('T', bound=ReaderInterface)


class RulesSource(Generic[T]):
    """Source of rules read with given ReaderInterface."""

    def __init__(self, source_handler: T) -> None:
        """Sets the source reader.

        Args:
            source_handler (ReaderInterface): Object used to read from.
        """
        self._handler = source_handler

    def __enter__(self) -> None:
        """Enter method for context manager."""
        self.open()

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_tb: TracebackType | None) -> None:
        """Exit method for context manager."""
        self.close()

    def open(self) -> None:
        """Opens source."""
        self._handler.open()

    def close(self) -> None:
        """Closes source."""
        self._handler.close()

    def read_all_rules(self) -> set[Rule]:
        """Returns set of rules from external source.

        Returns:
            set[Rule]: Rules read from reader.

        Raises:
            ValidationError: If input data violates Rule's restrictions.
            TypeError: If JSON data is not array.
            Exception: Other types raised by read_all of given reader.
        """
        return {Rule(**rule) for rule in self._handler.read_all_rules()}

    def read_all_filters(self) -> set[PacketFilter]:
        """Returns set of filters from external source.

        Returns:
            set[PacketFilter]: Filters read from reader.

        Raises:
            ValidationError: If input data violates PacketFilter's restrictions.
            TypeError: If JSON data is not array.
            Exception: Other types raised by read_all of given reader.
        """
        return {PacketFilter(packet_filter) for packet_filter in self._handler.read_all_filters()}

    def read_all_owners(self) -> set[Owner]:
        """Returns set of owners from external source.

        Returns:
            set[str]: Owners read from reader.

        Raises:
            TypeError: If JSON data is not array or owner is not string.
            Exception: Other types raised by read_all of given reader.
        """
        owners = self._handler.read_all_owners()
        if any(not isinstance(owner, str) for owner in owners):
            msg = 'Not all owners are strings'
            raise TypeError(msg)
        return {Owner(owner) for owner in owners}
