"""Importing rules from external source."""

import json
from pathlib import Path
from typing import Any
from typing import Protocol

from net_configurator.rule import Rule


class ReaderInterface(Protocol):
    """Interface with method read_all."""

    def read_all(self) -> list[Any]:
        """read_all stub."""
        ...


class JSONFileReader:
    """Reader for JSON formatted files."""

    def __init__(self, path: str | Path) -> None:
        """Sets the source path."""
        self.__path = Path(path)

    def read_all(self) -> list[Any]:
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


class RulesSource:
    """Source of input rules."""

    def __init__(self, source: ReaderInterface) -> None:
        """Sets the source."""
        self.__source = source

    def read_all(self) -> list[Rule]:
        """Returns dict of rules from external source.

        Returns:
            list[Rule]: Dict of Rule read from source.

        Raises:
            ValidationError: If input data violates Rule's restrictions.
            TypeError: If JSON data is not array.
            Exception: Other types raised by read_all of given reader.
        """
        return [Rule(**rule) for rule in self.__source.read_all()]
