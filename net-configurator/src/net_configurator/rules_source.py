"""Importing rules from external source."""

from types import TracebackType
from typing import Any
from typing import Protocol

from pydantic import ValidationError

from net_configurator.base_exceptions import FatalError
from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule


class DeserializationError(FatalError):
    """Exception raised when external data cannot be deserialized."""


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


class ReaderFactoryInterface(Protocol):
    """Interface of factory creating Reader."""

    def create(self) -> ReaderInterface:
        """Create Reader."""
        ...


class RulesSource:
    """Source of rules read with given ReaderInterface."""

    def __init__(self, source_handler: ReaderInterface) -> None:
        """Sets the source handler.

        Args:
            source_handler (ReaderInterface): Object used to read from.
        """
        self._handler = source_handler

    def __enter__(self) -> None:
        """Enter method for context manager.

        Raises:
            Exception: Exceptions raised by open of given handler.
        """
        self.open()

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_tb: TracebackType | None) -> None:
        """Exit method for context manager.

        Raises:
            Exception: Exceptions raised by close of given handler.
        """
        self.close()

    def open(self) -> None:
        """Opens source.

        Raises:
            Exception: Exceptions raised by open of given handler.
        """
        self._handler.open()

    def close(self) -> None:
        """Closes source.

        Raises:
            Exception: Exceptions raised by close of given handler.
        """
        self._handler.close()

    def read_all_rules(self) -> set[Rule]:
        """Returns set of rules from external source.

        Returns:
            set[Rule]: Rules read from handler.

        Raises:
            DeserializationError: when rules cannot be deserialized.
            Exception: Exceptions raised by read_all_rules of given handler.
        """
        try:
            return {Rule(**rule) for rule in self._handler.read_all_rules()}
        except ValidationError as e:
            msg = 'Rules cannot be deserialized'
            raise DeserializationError(msg) from e

    def read_all_filters(self) -> set[PacketFilter]:
        """Returns set of filters from external source.

        Returns:
            set[PacketFilter]: Filters read from handler.

        Raises:
            DeserializationError: when filters cannot be deserialized.
            Exception: Exceptions raised by read_all_filters of given handler.
        """
        try:
            return {PacketFilter(packet_filter) for packet_filter in self._handler.read_all_filters()}
        except ValidationError as e:
            msg = 'Filters cannot be deserialized'
            raise DeserializationError(msg) from e

    def read_all_owners(self) -> set[Owner]:
        """Returns set of owners from external source.

        Returns:
            set[Owner]: Owners read from handler.

        Raises:
            DeserializationError: when owners cannot be deserialized.
            Exception: Exceptions raised by read_all_owners of given handler.
        """
        owners = self._handler.read_all_owners()
        try:
            return {Owner(owner) for owner in owners}
        except ValidationError as e:
            msg = 'Owners cannot be deserialized'
            raise DeserializationError(msg) from e
