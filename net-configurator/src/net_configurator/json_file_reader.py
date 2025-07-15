"""Reader for JSON formatted files."""

from functools import cached_property
import json
from pathlib import Path
from types import TracebackType
from typing import Any
from typing import IO


class FileAccessError(Exception):
    """Exception raised in case of problems accessing file."""


class FileNotOpenedError(RuntimeError):
    """Exception raised when reading from closed file."""


class NotJSONArrayError(TypeError):
    """Exception raised when top-level file element is not array."""


class JSONFileReader:
    """Reader for JSON formatted files."""

    _file_mode: str = 'r'

    def __init__(self, path: str | Path) -> None:
        """Sets the source path.

        Args:
            path (str | Path): Path of source file.
        """
        self.__path = Path(path)
        self._file: IO[str] | None = None

    def __enter__(self) -> None:
        """Enter method for context manager.

        Raises:
            FileAccessError: If file cannot be opened.
        """
        self.open()

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_tb: TracebackType | None) -> None:
        """Exit method for context manager.

        Raises:
            FileAccessError: If file cannot be closed.
        """
        self.close()

    def open(self) -> None:
        """Opens file.

        Raises:
            FileAccessError: If file cannot be opened.
        """
        if not self._file:
            try:
                self._file = self.__path.open(mode=self._file_mode)
            except (FileNotFoundError, IsADirectoryError, NotADirectoryError, OSError, PermissionError) as e:
                msg = f'Cannot open {self.__path!s}'
                raise FileAccessError(msg) from e

    def close(self) -> None:
        """Closes file.

        Raises:
            FileAccessError: If file cannot be closed.
        """
        if self._file:
            try:
                self._file.close()
            except OSError as e:
                msg = f'Cannot close {self.__path!s}'
                raise FileAccessError(msg) from e
            self._file = None

    @cached_property
    def _file_decoded(self) -> list[Any]:
        """Returns JSON array from file as list.

        Returns:
            list: List of values read from JSON file.

        Raises:
            FileNotOpenedError: If file has not beed opened.
            NotJSONArrayError: If JSON is not valid or not array.
        """
        if self._file:
            try:
                data = json.load(self._file)
            except json.JSONDecodeError as e:
                msg = 'File content is not valid JSON'
                raise NotJSONArrayError(msg) from e
            if not isinstance(data, list):
                msg = 'File content is not an array'
                raise NotJSONArrayError(msg)
            return data
        msg = 'File not opened before reading'
        raise FileNotOpenedError(msg)

    def read_all_rules(self) -> list[Any]:
        """Returns JSON array from file as list.

        Returns:
            list: List of values read from JSON file.

        Raises:
            FileNotOpenedError: If file has not beed opened.
            NotJSONArrayError: If JSON is not valid or not array.
        """
        return self._file_decoded

    def read_all_filters(self) -> list[Any]:
        """Returns packet_filter JSON objects from file as list.

        Returns:
            list: List of packet_filter values read from JSON file.

        Raises:
            FileNotOpenedError: If file has not beed opened.
            NotJSONArrayError: If JSON is not valid or not array.
        """
        return [rule['packet_filter'] for rule in self._file_decoded if isinstance(rule, dict) and 'packet_filter' in rule]

    def read_all_owners(self) -> list[str]:
        """Returns owners from file as list.

        Returns:
            list: List of owners values read from JSON file.

        Raises:
            FileNotOpenedError: If file has not beed opened.
            NotJSONArrayError: If JSON is not valid or not array.
        """
        owner_lists = [rule['owners'] for rule in self._file_decoded if isinstance(rule, dict) and 'owners' in rule]
        return [owner for owner_list in owner_lists for owner in owner_list]
