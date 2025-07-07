"""RuleTarget represents destination for rules."""

from pathlib import Path
from typing import Protocol

from pydantic import RootModel

from net_configurator.rule import Rule
from net_configurator.rules_source import ReaderInterface
from net_configurator.rules_source import RulesSource


class WriterInterface(Protocol):
    """Interface with methods for changing rules."""

    def add_rule(self, rule: Rule) -> None:
        """add_rule stub."""
        ...

    def delete_rule(self, rule_identifier: str) -> None:
        """delete_rule stub."""
        ...

    def apply_changes(self) -> None:
        """apply_changes stub."""
        ...


class JSONFileWriter:
    """Writer for JSON formatted files."""

    def __init__(self, path: str | Path) -> None:
        """Sets the destination path.

        Args:
            path (str | Path): Path of destination file.
        """
        self.__path = Path(path)
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
        with self.__path.open(mode='w') as file:
            file.write(rules.model_dump_json(indent=2, exclude_none=True))


class RulesTarget(RulesSource):
    """Target for rules to be read (ReaderInterface) and written (WriterInterface)."""

    def __init__(self, target_reader: ReaderInterface, target_writer: WriterInterface) -> None:
        """Sets target's reader and writer.

        Target reader and writer can be the same object.

        Args:
            target_reader (ReaderInterface): Object used to read rules from.
            target_writer (WriterInterface): Object used to write rules to.
        """
        super().__init__(source_reader=target_reader)
        self.__writer = target_writer

    def add_rule(self, rule: Rule) -> None:
        """Adds rule to target writer.

        Args:
            rule (Rule): Rule to add.
        """
        self.__writer.add_rule(rule)

    def delete_rule(self, rule_identifier: str) -> None:
        """Deletes rule at target writer.

        Args:
            rule_identifier (str): Identifier of rule to delete.
        """
        self.__writer.delete_rule(rule_identifier)

    def apply_changes(self) -> None:
        """Applies changes to target writer.

        Raises:
            Exception: Exceptions raised by apply_changes of given target writer.
        """
        self.__writer.apply_changes()
