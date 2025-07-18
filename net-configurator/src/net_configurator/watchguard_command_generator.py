"""Classes for generating WatchGuard-specific commands."""

from contextlib import contextmanager
from typing import Iterator

from net_configurator.rule import NetworkPeer
from net_configurator.rule import NetworkService
from net_configurator.rule import Rule
from net_configurator.rule import RuleFilter


class WatchguardCommandGenerator:
    """WatchGuard-specific command generator."""
    
    def __init__(self, commands: Optional[list[str]] = None) -> None:
        """Placeholder."""
        self.commands = commands if commands is not None
        self.command_helper = WatchguardCommandGeneratorHelper()
    
    @staticmethod
    def add_rule(rule: Rule):
        """Generate commands to add a rule.

        Args:
            rule (Rule): The rule to add.

        Returns:
            list[str]: A list of generated commands.
        """
        with self.enter_config_context(), self.enter_policy_context(), self.enter_rule_context(rule.identifier):
            self.commands.append(f'policy-type {rule.filter.identifier} {self.command_helper.build_from(rule)} {self.command_helper.build_to(rule)}')
            self.commands.append(f'policy-tag {self.command_helper.build_owners(rule.owners)}')
            self.commands.append('apply')

    @staticmethod
    def delete_rule(name: str):
        """Generate command to delete a rule.

        Args:
            name (str): Rule name to delete.

        Returns:
            str: A generated command.
        """
        self.commands.append(f'no rule {name}')

    @staticmethod
    def read_rules():
        """Generate command to read all rules.

        Returns:
            str: A generated command.
        """
        self.commands.append('show rule')

    def read_owners():
        """Generate command to read tags.

        Returns:
            str: A generated command.
        """
        self.commands.append('show policy-type')

    def read_rule(name: str) -> str:
        """Generate command to read a specific rule.

        Args:
            name (str): Rule name to read.

        Returns:
            str: A generated command.
        """
        self.commands.append(f'show rule {name}')

    @staticmethod
    def add_owner(owners: tuple[str, ...]):
        """Generate commands to add a owner tags.

        Args:
            owners (tuple[str, ...]): List-like touple of owner tags.
        
        Returns:
            list[str]: A list of generated commands.
        """
        with self.enter_config_context(), self.command_helper.policy(commands):
            self.commands.extend([f'policy-tag {owner} color 0xc0c0c0' for owner in owners])

    @staticmethod
    def add_filter(rule_filter: RuleFilter) -> list[str]:
        """Generate commands to add a filter.

        Args:
            rule_filter (RuleFilter): The filter to be added.

        Returns:
            list[str]: A list of generated commands.
        """
        commands: list[str] = []
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
    
    
    def get_commands(self) -> None:
        """Placeholder."""
        return self.commands
    
    @contextmanager
    def enter_config_context(self) -> Iterator[None]:
        """Context manager to open and close a config block."""
        self.commands.append('config')
        try:
            yield
        finally:
            self.commands.append('exit')

    @contextmanager
    def enter_policy_context(self) -> Iterator[None]:
        """Context manager to open and close a policy block."""
        self.commands.append('policy')
        try:
            yield
        finally:
            self.commands.append('exit')

    @contextmanager
    def enter_rule_context(self, name: str) -> Iterator[None]:
        """Context manager to define a rule block.

        Args:
            commands (list[str]): List to append commands to.
            name (str): Rule name.
        """
        self.commands.append(f'rule {name}')
        try:
            yield
        finally:
            self.commands.append('exit')

    @contextmanager
    def enter_filter_context(self, name: str) -> Iterator[None]:
        """Context manager to define a filter block.

        Args:
            commands (list[str]): List to append commands to.
            name (str): Filter name.
        """
        self.commands.append(f'policy-type {name}')
        try:
            yield
        finally:
            self.commands.append('exit')

class WatchguardCommandGeneratorHelper:
    """Placeholder."""
    def build_network(self, networks: tuple[NetworkPeer, ...]) -> str:
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

    def build_service(self, service: NetworkService) -> str:
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
            parts.append(f'port-range {service.port_low} {service.port_high}')
        return ' '.join(parts)

    def build_from(self, rule: Rule) -> str:
        """Build the 'from' part of a rule command.

        Args:
            rule (Rule): Rule with source definitions.

        Returns:
            str: A command-ready source string.
        """
        return f'from {CommandBuilder.build_network(rule.sources)}'

    def build_to(self, rule: Rule) -> str:
        """Build the 'to' part of a rule command.

        Args:
            rule (Rule): Rule with destination definitions.

        Returns:
            str: A command-ready destination string.
        """
        return f'to {CommandBuilder.build_network(rule.destinations)}'

    def build_owners(self, owners: tuple[str, ...]) -> str:
        """Build the owners part of a rule command.

        Args:
            owners (tuple[str, ...]): List-like touple of owner tags.

        Returns:
            str: A string with owner tags.
        """
        return ' '.join(owners)
