"""Classes for generating WatchGuard-specific commands."""

from contextlib import contextmanager

from rule import NetworkPeer
from rule import NetworkService
from rule import Rule
from rule import RuleFilter


class CommandBuilder:
    """Helper class to format parts of WatchGuard command strings."""

    @staticmethod
    @contextmanager
    def config(commands: list[str]):
        """Context manager to open and close a config block."""
        commands.append('config')
        try:
            yield
        finally:
            commands.append('exit')

    @staticmethod
    @contextmanager
    def policy(commands: list[str]):
        """Context manager to open and close a policy block."""
        commands.append('policy')
        try:
            yield
        finally:
            commands.append('exit')

    @staticmethod
    @contextmanager
    def rule(commands: list[str], name: str):
        """Context manager to define a rule block.

        Args:
            commands (list[str]): List to append commands to.
            name (str): Rule name.
        """
        commands.append(f'rule {name}')
        try:
            yield
        finally:
            commands.append('exit')

    @staticmethod
    @contextmanager
    def filter(commands: list[str], name: str):
        """Context manager to define a filter block.

        Args:
            commands (list[str]): List to append commands to.
            name (str): Filter name.
        """
        commands.append(f'policy-type {name}')
        try:
            yield
        finally:
            commands.append('exit')

    @staticmethod
    def build_network(networks: list[NetworkPeer]) -> str:
        """Build network string from a list of NetworkPeer objects.

        Args:
            networks (list[NetworkPeer]): List of networks.

        Returns:
            str: A command-ready network string.
        """
        parts = []
        for network in networks:
            if network.is_address_single():
                parts.append(f'host-ip {network.ip_low}')
            elif network.is_address_range():
                parts.append(f'host-range {network.ip_low} {network.ip_high}')
            else:
                parts.append(f'network-ip {network.ip_low}')
        return ' '.join(parts)

    @staticmethod
    def build_service(service: NetworkService) -> str:
        """Build service string from a NetworkService object.

        Args:
            service (NetworkService): A service to describe.

        Returns:
            str: A command-ready service string.
        """
        parts = [f'protocol {service.protocol}']
        if service.protocol == 'icmp':
            parts.append('Any 255')
        elif service.is_port_single():
            parts.append(f'{service.port_low}')
        else:
            parts.append(f'port-range {service.port_low} {service.port_low}')
        return ' '.join(parts)

    @staticmethod
    def build_from(rule: Rule) -> str:
        """Build the 'from' part of a rule command.

        Args:
            rule (Rule): Rule with source definitions.

        Returns:
            str: A command-ready source string.
        """
        return f'from {CommandBuilder.build_network(rule.sources)}'

    @staticmethod
    def build_to(rule: Rule) -> str:
        """Build the 'to' part of a rule command.

        Args:
            rule (Rule): Rule with destination definitions.

        Returns:
            str: A command-ready destination string.
        """
        return f'to {CommandBuilder.build_network(rule.destinations)}'
    
    @staticmethod
    def build_owners(owners: tuple[str, ...]) -> str:
        """Build the owners part of a rule command.

        Args:
            rule (Rule): Rule with destination definitions.

        Returns:
            str: A command-ready destination string.
        """
        return " ".join(owners)


class WatchguardCommandGenerator:
    """WatchGuard-specific command generator."""

    @staticmethod
    def add_rule(rule: Rule) -> list[str]:
        """Generate commands to add a rule.

        Args:
            rule (Rule): The rule to add.

        Returns:
            list[str]: A list of generated commands.
        """
        commands = []
        with CommandBuilder.config(commands), CommandBuilder.policy(commands), CommandBuilder.rule(commands, rule.identifier):
            commands.append(f'policy-type {rule.filter.identifier} {CommandBuilder.build_from(rule)} {CommandBuilder.build_to(rule)}')
            commands.append(f'policy-tag {CommandBuilder.build_owners(rule.owners)}')
            commands.append('apply')

        return commands

    @staticmethod
    def delete_rule(name: str) -> str:
        """Generate command to delete a rule.

        Args:
            name (str): Rule name to delete.

        Returns:
            str: A generated command.
        """
        return f'no rule {name}'

    @staticmethod
    def read_rules() -> str:
        """Generate command to read all rules.

        Returns:
            str: A generated command.
        """
        return 'show rule'
    
    @staticmethod
    def read_owners(name: str) -> str:
        """Generate command to read a specific rule.

        Args:
            name (str): Rule name to read.

        Returns:
            str: A generated command.
        """
        return f'show policy-type'

    @staticmethod
    def read_rule(name: str) -> str:
        """Generate command to read a specific rule.

        Args:
            name (str): Rule name to read.

        Returns:
            str: A generated command.
        """
        return f'show rule {name}'
    
    @staticmethod
    def add_owner(owners: tuple[str, ...]) -> list[str]:
        """Generate commands to add a filter.

        Args:
            rule_filter (RuleFilter): The filter to be added.

        Returns:
            list[str]: A list of generated commands.
        """
        commands = []
        with CommandBuilder.config(commands), CommandBuilder.policy(commands):
            commands.extend([f'policy-tag {owner} color 0xc0c0c0' for owner in owners])

        return commands

    @staticmethod
    def add_filter(rule_filter: RuleFilter) -> list[str]:
        """Generate commands to add a filter.

        Args:
            rule_filter (RuleFilter): The filter to be added.

        Returns:
            list[str]: A list of generated commands.
        """
        commands = []
        with CommandBuilder.config(commands), CommandBuilder.policy(commands):
            commands.extend([f'policy-type {rule_filter.identifier} {CommandBuilder.build_service(service)}' for service in rule_filter.root])
            commands.append('apply')

        return commands

    @staticmethod
    def delete_filter(name: str) -> list[str]:
        """Generate command to delete a filter.

        Args:
            name (str): Name of the filter to delete.

        Returns:
            list[str]: A list of generated commands.
        """
        return [f'no policy-type {name}']

    @staticmethod
    def read_filters() -> str:
        """Generate command to list managed filters.

        Returns:
            str: A generated command.
        """
        return 'show policy-type'

    @staticmethod
    def read_filter(name: str) -> str:
        """Generate command to read a specific filter.

        Args:
            name (str): Name of the filter.

        Returns:
            str: A generated command.
        """
        return f'show policy-type {name}'
