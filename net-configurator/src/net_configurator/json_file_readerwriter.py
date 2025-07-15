"""Reader/writer for JSON formatted files."""

from pathlib import Path

from pydantic import RootModel

from net_configurator.json_file_reader import FileNotOpenedError
from net_configurator.json_file_reader import JSONFileReader
from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule


class JSONFileReaderWriter(JSONFileReader):
    """Reader/writer for JSON formatted files."""

    _file_mode: str = 'r+'

    def __init__(self, path: str | Path) -> None:
        """Sets the destination path.

        Args:
            path (str | Path): Path of destination file.
        """
        super().__init__(path)
        self.__rules: set[Rule] = set()

    def add_rule(self, rule: Rule) -> None:
        """Adds rule to file.

        Args:
            rule (Rule): Rule to add.
        """
        self.__rules.add(rule)

    def delete_rule(self, rule_identifier: str) -> None:
        """Deletes rule from file.

        Args:
            rule_identifier (str): Identifier of rule to delete.
        """
        rule_to_delete = next((rule for rule in self.__rules if rule.identifier == rule_identifier), None)
        if rule_to_delete:
            self.__rules.discard(rule_to_delete)

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """Adds packet filter to file.

        Method is not implemented - no need to do antyhing in file.

        Args:
            packet_filter (PacketFilter): Packet filter to add.
        """

    def delete_filter(self, filter_identifier: str) -> None:
        """Deletes packet filter from file.

        Method is not implemented - no need to do antyhing in file.

        Args:
            filter_identifier (str): Identifier of packet filter to delete.
        """

    def add_owner(self, owner: Owner) -> None:
        """Adds owner to file.

        Method is not implemented - no need to do antyhing in file.

        Args:
            owner (Owner): Owner to add.
        """

    def delete_owner(self, owner_identifier: str) -> None:
        """Deletes owner from file.

        Method is not implemented - no need to do antyhing in file.

        Args:
            owner_identifier (str): Identifier of owner to delete.
        """

    def apply_changes(self) -> None:
        """Creates file with applied changes.

        Raises:
            FileNotFoundError: If parent directory not found.
            IsADirectoryError: If path is a directory.
            NotADirectoryError: If parent in path is not directory.
            OSError: For low level errors while reading file.
            PermissionError: If permissions do not allow to open file.
        """
        RuleList = RootModel[list[Rule]]  # noqa: N806
        rules = RuleList(list(self.__rules))
        if self._file:
            self._file.write(rules.model_dump_json(indent=2, exclude_none=True))
        else:
            msg = 'File not opened before writing'
            raise FileNotOpenedError(msg)
