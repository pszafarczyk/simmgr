"""Importing rules from external source."""

from functools import cached_property
import json
from pathlib import Path
from typing import Any
from typing import Protocol

from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule


class ReaderInterface(Protocol):
    """Interface with method read_all."""

    def read_all_rules(self) -> list[Any]:
        """read_all_rules stub."""
        ...

    def read_all_filters(self) -> list[Any]:
        """read_all_filters stub."""
        ...

    def read_all_owners(self) -> list[str]:
        """read_all_owners stub."""
        ...


class JSONFileReader:
    """Reader for JSON formatted files."""

    def __init__(self, path: str | Path) -> None:
        """Sets the source path.

        Args:
            path (str | Path): Path of source file.
        """
        self.__path = Path(path)

    @cached_property
    def __file_decoded(self) -> list[Any]:
        """Returns JSON array from file as list.

        Returns:
            list: List of values read from JSON file.

        Raises:
            FileNotFoundError: If source file cannot be found.
            IsADirectoryError: If path is a directory.
            JSONDecodeError: If content is not valid JSON data
            NotADirectoryError: If parent in path is not directory.
            OSError: For low level errors while reading file.
            PermissionError: If permissions do not allow to open file.
            TypeError: If JSON data is not array.
        """
        with self.__path.open() as file:
            data = json.load(file)
            if not isinstance(data, list):
                msg = 'File content is not an array'
                raise TypeError(msg)
            return data

    def read_all_rules(self) -> list[Any]:
        """Returns JSON array from file as list.

        Returns:
            list: List of values read from JSON file.

        Raises:
            FileNotFoundError: If source file cannot be found.
            IsADirectoryError: If path is a directory.
            JSONDecodeError: If content is not valid JSON data
            NotADirectoryError: If parent in path is not directory.
            OSError: For low level errors while reading file.
            PermissionError: If permissions do not allow to open file.
            TypeError: If JSON data is not array.
        """
        return self.__file_decoded

    def read_all_filters(self) -> list[Any]:
        """Returns packet_filter JSON objects from file as list.

        Returns:
            list: List of packet_filter values read from JSON file.

        Raises:
            FileNotFoundError: If source file cannot be found.
            IsADirectoryError: If path is a directory.
            JSONDecodeError: If content is not valid JSON data
            NotADirectoryError: If parent in path is not directory.
            OSError: For low level errors while reading file.
            PermissionError: If permissions do not allow to open file.
            TypeError: If JSON data is not array.
        """
        return [rule['packet_filter'] for rule in self.__file_decoded if isinstance(rule, dict) and 'packet_filter' in rule]

    def read_all_owners(self) -> list[str]:
        """Returns owners from file as list.

        Returns:
            list: List of owners values read from JSON file.

        Raises:
            FileNotFoundError: If source file cannot be found.
            IsADirectoryError: If path is a directory.
            JSONDecodeError: If content is not valid JSON data
            NotADirectoryError: If parent in path is not directory.
            OSError: For low level errors while reading file.
            PermissionError: If permissions do not allow to open file.
            TypeError: If JSON data is not array.
        """
        owner_lists = [rule['owners'] for rule in self.__file_decoded if isinstance(rule, dict) and 'owners' in rule]
        return [owner for owner_list in owner_lists for owner in owner_list]


class RulesSource:
    """Source of rules read with given ReaderInterface."""

    def __init__(self, source_reader: ReaderInterface) -> None:
        """Sets the source reader.

        Args:
            source_reader (ReaderInterface): Object used to read rules from.
        """
        self.__reader = source_reader

    def read_all_rules(self) -> set[Rule]:
        """Returns set of rules from external source.

        Returns:
            set[Rule]: Rules read from reader.

        Raises:
            ValidationError: If input data violates Rule's restrictions.
            TypeError: If JSON data is not array.
            Exception: Other types raised by read_all of given reader.
        """
        return {Rule(**rule) for rule in self.__reader.read_all_rules()}

    def read_all_filters(self) -> set[PacketFilter]:
        """Returns set of filters from external source.

        Returns:
            set[PacketFilter]: Filters read from reader.

        Raises:
            ValidationError: If input data violates PacketFilter's restrictions.
            TypeError: If JSON data is not array.
            Exception: Other types raised by read_all of given reader.
        """
        return {PacketFilter(packet_filter) for packet_filter in self.__reader.read_all_filters()}

    def read_all_owners(self) -> set[str]:
        """Returns set of owners from external source.

        Returns:
            set[str]: Owners read from reader.

        Raises:
            TypeError: If JSON data is not array or owner is not string.
            Exception: Other types raised by read_all of given reader.
        """
        owners = self.__reader.read_all_owners()
        if any(not isinstance(owner, str) for owner in owners):
            msg = 'Not all owners are strings'
            raise TypeError(msg)
        return set(owners)
