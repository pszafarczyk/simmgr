"""Reader for JSON formatted files."""

from functools import cached_property
import json
from pathlib import Path
from types import TracebackType
from typing import Any
from typing import IO


class FileNotOpenedError(RuntimeError):
    """Exception raised when reading from closed file."""


class NotJSONArrayError(TypeError):
    """Exception raised when top-level file element is not array."""


class JSONFileReader:
    """Reader for JSON formatted files."""

    def __init__(self, path: str | Path) -> None:
        """Sets the source path.

        Args:
            path (str | Path): Path of source file.
        """
        self.__path = Path(path)
        self.__file: IO[str] | None = None

    def __enter__(self) -> None:
        """Enter method for context manager."""
        self.open()

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_tb: TracebackType | None) -> None:
        """Exit method for context manager."""
        self.close()

    def open(self) -> None:
        """Opens file."""
        if not self.__file:
            self.__file = self.__path.open()

    def close(self) -> None:
        """Closes file."""
        if self.__file:
            self.__file.close()
            self.__file = None

    @cached_property
    def __file_decoded(self) -> list[Any]:
        """Returns JSON array from file as list.

        Returns:
            list: List of values read from JSON file.

        Raises:
            FileNotFoundError: If source file cannot be found.
            FileNotOpened: If file has not been opened.
            IsADirectoryError: If path is a directory.
            JSONDecodeError: If content is not valid JSON data
            NotADirectoryError: If parent in path is not directory.
            NotJSONArrayError: If JSON data is not array.
            OSError: For low level errors while reading file.
            PermissionError: If permissions do not allow to open file.
        """
        if self.__file:
            data = json.load(self.__file)
            if not isinstance(data, list):
                msg = 'File content is not an array'
                raise NotJSONArrayError(msg)
            return data
        msg = 'File not opened before accessing'
        raise FileNotOpenedError(msg)

    def read_all_rules(self) -> list[Any]:
        """Returns JSON array from file as list.

        Returns:
            list: List of values read from JSON file.

        Raises:
            FileNotFoundError: If source file cannot be found.
            FileNotOpened: If file has not been opened.
            IsADirectoryError: If path is a directory.
            JSONDecodeError: If content is not valid JSON data
            NotADirectoryError: If parent in path is not directory.
            NotJSONArrayError: If JSON data is not array.
            OSError: For low level errors while reading file.
            PermissionError: If permissions do not allow to open file.
        """
        return self.__file_decoded

    def read_all_filters(self) -> list[Any]:
        """Returns packet_filter JSON objects from file as list.

        Returns:
            list: List of packet_filter values read from JSON file.

        Raises:
            FileNotFoundError: If source file cannot be found.
            FileNotOpened: If file has not been opened.
            IsADirectoryError: If path is a directory.
            JSONDecodeError: If content is not valid JSON data
            NotADirectoryError: If parent in path is not directory.
            NotJSONArrayError: If JSON data is not array.
            OSError: For low level errors while reading file.
            PermissionError: If permissions do not allow to open file.
        """
        return [rule['packet_filter'] for rule in self.__file_decoded if isinstance(rule, dict) and 'packet_filter' in rule]

    def read_all_owners(self) -> list[str]:
        """Returns owners from file as list.

        Returns:
            list: List of owners values read from JSON file.

        Raises:
            FileNotFoundError: If source file cannot be found.
            FileNotOpened: If file has not been opened.
            IsADirectoryError: If path is a directory.
            JSONDecodeError: If content is not valid JSON data
            NotADirectoryError: If parent in path is not directory.
            NotJSONArrayError: If JSON data is not array.
            OSError: For low level errors while reading file.
            PermissionError: If permissions do not allow to open file.
        """
        owner_lists = [rule['owners'] for rule in self.__file_decoded if isinstance(rule, dict) and 'owners' in rule]
        return [owner for owner_list in owner_lists for owner in owner_list]
