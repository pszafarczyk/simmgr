"""Classes for generating watchguard specific commands."""
from rule import NamedRule
from rule import RuleFilter


class WatchguardCommandGenerator:
    """Watchguard specific command generator."""

    def add_rule(self, rule: NamedRule) -> list[str]:
        """Generate add Rule command.

        Args:
            rule (NamedRule): NamedRule object to add.

        Returns:
            str: A list of generated commands.
        """
        command = []
        """
            f'policy add name Rule_{rule.identifier} '

            f'policy-type {rule.name}-policy '
            f'from '
        for sorce in rule.sources:
        for destination in rule.destinations:
            
            f'to host-range {rule.destination[0]} {rule.destination[-1]} '
            f'port {rule.port} protocol {rule.protocol} '
            f'action {rule.action} enable'
        """

    def delete_rule(self, name: str) -> list[str]:
        """Generate delete Rule command.

        Args:
            names (str): Rule name to delete.

        Returns:
            str: A list of generated commands.
        """
        command = []
    def read_rules(self) -> str:
        """Generate read Rulles command.

        Returns:
            str: A generated command.
        """
        command = 'show policy-type'
        return command

    def add_filter(self, rule: RuleFilter) -> list[str]:
        """Generate add Filter command.

        Args:
            rules (list[NamedRule]): A list of NamedRule objects to be added.

        Returns:
            str: A list of generated command.
        """

    def delete_filter(self, name: str) -> list[str]:
        """Add delete Rule order to the queue.

        Args:
            names (list[str]): A list of rule names to delete.

        Returns:
            str: A list of generated commands.
        """

    def read_managed_filters(self) -> str:
        """Retrieve the list of Rules currently managed by this manager.

        Returns:
            str: A generated command.
        """
        command = 'show policy-type'
        return command


