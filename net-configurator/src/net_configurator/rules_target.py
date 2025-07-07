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
        """Sets the destination path."""
        self.__path = Path(path)
        self.__rules: set[Rule] = set()

    def add_rule(self, rule: Rule) -> None:
        """Adds rule to file."""
        self.__rules.add(rule)

    def delete_rule(self, rule_identifier: str) -> None:
        """Deletes rule from file."""
        rule_to_delete = next((rule for rule in self.__rules if rule.identifier == rule_identifier), None)
        if rule_to_delete:
            self.__rules.discard(rule_to_delete)

    def apply_changes(self) -> None:
        """Applys changes to file."""
        RuleList = RootModel[list[Rule]]  # noqa: N806
        rules = RuleList(list(self.__rules))
        with self.__path.open(mode='w') as file:
            file.write(rules.model_dump_json(indent=2, exclude_none=True))
