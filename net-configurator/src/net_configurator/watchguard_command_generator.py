"""Classes for generating WatchGuard-specific commands."""

from rule import Rule, RuleFilter, NetworkPeer, NetworkService
from contextlib import contextmanager


class RuleFormatter:
    @staticmethod
    @contextmanager
    def config(commands: list[str]):
        commands.append('config')
        try:
            yield
        finally:
            commands.append('exit')

    @staticmethod
    @contextmanager
    def policy(commands: list[str]):
        commands.append('policy')
        try:
            yield
        finally:
            commands.append('exit')

    @staticmethod
    @contextmanager
    def rule(commands: list[str], name: str):
        commands.append(f'rule {name}')
        try:
            yield
        finally:
            commands.append('exit')

    @staticmethod
    @contextmanager
    def filter(commands: list[str], name: str):
        commands.append(f'policy-type {name}')
        try:
            yield
        finally:
            commands.append('exit')

    @staticmethod
    def build_network(networks: list[NetworkPeer]) -> str:
        parts = []
        for network in networks:
            if network.is_address_single():
                parts.append(f"host-ip {network.ip_low}")
            elif network.is_address_range():
                parts.append(f"host-range {network.ip_low} {network.ip_high}")
            elif network.is_address_single():
                parts.append(f"network-ip {network.ip_low}")
        return ' '.join(parts)

    @staticmethod
    def build_service(service: NetworkService) -> str:
        parts = []
        parts.append(f'protocol {service.protocol}')
        if service.protocol == 'icmp':
            parts.append(f'Any 255')
        else:
            if service.is_port_single():
                parts.append(f'{service.port_low}') 
            else:
                parts.append(f'port-range {service.port_low} {service.port_low}')
        return ' '.join(parts)


    @staticmethod
    def build_from(rule: Rule) -> str:
        return f'from {RuleFormatter.build_network(rule.sources)}'

    @staticmethod
    def build_to(rule: Rule) -> str:
        return f'to {RuleFormatter.build_network(rule.destinations)}'


class WatchguardCommandGenerator:
    """WatchGuard-specific command generator."""

    @staticmethod
    def add_rule(rule: Rule) -> list[str]:
        """Generate commands to add a rule."""
        commands = []
        with RuleFormatter.config(commands), \
             RuleFormatter.policy(commands), \
             RuleFormatter.rule(commands, rule.identifier):

            commands.append(
                f'policy-type {rule.filter.identifier} '
                f'{RuleFormatter.build_from(rule)} '
                f'{RuleFormatter.build_to(rule)}'
            )
            commands.append('apply')

        return commands

    @staticmethod
    def delete_rule(name: str) -> list[str]:
        """Generate command to delete a rule.

        Args:
            name (str): Rule name to delete.

        Returns:
            list[str]: A list of generated commands.
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
    def read_rule(name: str) -> str:
        """Generate command to read all rules.

        Returns:
            str: A generated command.
        """
        return f'show rule {name}'

    @staticmethod
    def add_filter(filter: RuleFilter) -> list[str]:
        """Generate commands to add a filter.

        Args:
            rule_filter (RuleFilter): The filter to be added.

        Returns:
            list[str]: A list of generated commands.
        """
        commands = []
        with RuleFormatter.config(commands), \
             RuleFormatter.policy(commands):
            for service in filter.root: 
                commands.append(
                    f'policy-type {filter.identifier} '
                    f'{RuleFormatter.build_service(service)}'
                )
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
        """Generate command to read all rules.

        Returns:
            str: A generated command.
        """
        return f'show policy-type {name}'
