"""Reader/writer for JSON formatted files."""

import logging
from pathlib import Path

from pydantic import RootModel

from net_configurator.json_file_reader import FileAccessError
from net_configurator.json_file_reader import FileNotOpenedError
from net_configurator.json_file_reader import JSONFileReader
from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule
from net_configurator.rules_source import RulesSource


class JSONFileReaderWriter(JSONFileReader):
    """Reader/writer for JSON formatted files."""

    _file_mode: str = 'r+'

    def __init__(self, path: str | Path) -> None:
        """Sets the destination path and load existing rules.

        Args:
            path (str | Path): Path of destination file.
        """
        super().__init__(path)
        self.__logger = logging.getLogger(self.__class__.__name__)
        self.__logger.debug('Using RulesSource to read initial content of file')
        rules_source = RulesSource(self)
        with rules_source:
            self.__rules = rules_source.read_all_rules()

    def add_rule(self, rule: Rule) -> None:
        """Adds rule to file.

        Args:
            rule (Rule): Rule to add.
        """
        self.__logger.debug('Rule %s add requested', rule.identifier)
        self.__rules.add(rule)
        self.__logger.debug('Rule %s added', rule.identifier)

    def delete_rule(self, rule_identifier: str) -> None:
        """Deletes rule from file.

        Args:
            rule_identifier (str): Identifier of rule to delete.
        """
        self.__logger.debug('Rule %s delete requested', rule_identifier)
        rule_to_delete = next((rule for rule in self.__rules if rule.identifier == rule_identifier), None)
        if rule_to_delete:
            self.__rules.discard(rule_to_delete)
            self.__logger.debug('Rule %s deleted', rule_to_delete.identifier)

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """Adds packet filter to file.

        Method is not implemented - no need to do antyhing in file.

        Args:
            packet_filter (PacketFilter): Packet filter to add.
        """
        self.__logger.debug('Filter %s add requested', packet_filter.identifier)
        self.__logger.debug('Filter add skipped - for file not needed')

    def delete_filter(self, filter_identifier: str) -> None:
        """Deletes packet filter from file.

        Method is not implemented - no need to do antyhing in file.

        Args:
            filter_identifier (str): Identifier of packet filter to delete.
        """
        self.__logger.debug('Filter %s delete requested', filter_identifier)
        self.__logger.debug('Filter delete skipped - for file not needed')

    def add_owner(self, owner: Owner) -> None:
        """Adds owner to file.

        Method is not implemented - no need to do antyhing in file.

        Args:
            owner (Owner): Owner to add.
        """
        self.__logger.debug('Owner %s add requested', owner.identifier)
        self.__logger.debug('Owner add skipped - for file not needed')

    def delete_owner(self, owner_identifier: str) -> None:
        """Deletes owner from file.

        Method is not implemented - no need to do antyhing in file.

        Args:
            owner_identifier (str): Identifier of owner to delete.
        """
        self.__logger.debug('Owner %s delete requested', owner_identifier)
        self.__logger.debug('Owner delete skipped - for file not needed')

    def apply_changes(self) -> None:
        """Creates file with applied changes.

        Raises:
            FileAccessError: If writing to file is not possible.
            FileNotOpenedError: If file has not beed opened.
        """
        self.__logger.debug('Apply changes requested')
        RuleList = RootModel[list[Rule]]  # noqa: N806
        rules = RuleList(list(self.__rules))
        if self._file:
            try:
                self._file.seek(0)
                self._file.write(rules.model_dump_json(indent=2, exclude_none=True))
                self._file.truncate()
                self.__logger.debug('Changes written to file')
            except OSError as e:
                msg = 'Cannot write to file'
                raise FileAccessError(msg) from e
        else:
            msg = 'File not opened before writing'
            raise FileNotOpenedError(msg)


class JSONFileReaderWriterFactory:
    """Factory creating JSONFileReaderWriter."""

    def __init__(self, path: str | Path) -> None:
        """Sets the source path.

        Args:
            path (str | Path): Path of target file.
        """
        self.__path = Path(path)

    def create(self) -> JSONFileReaderWriter:
        """Creates JSONFileReaderWriter.

        Returns:
            JSONFileReaderWriter: New JSONFileReaderWriter.
        """
        return JSONFileReaderWriter(self.__path)
