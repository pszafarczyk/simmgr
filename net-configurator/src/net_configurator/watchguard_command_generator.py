"""Classes for generating WatchGuard-specific commands."""

from collections.abc import Iterator
from contextlib import contextmanager

from net_configurator.rule import NetworkPeer
from net_configurator.rule import NetworkService
from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule


class WatchguardCommandGenerator:
    """WatchGuard-specific command generator."""

    def __init__(self, commands: list[str] | None = None) -> None:
        """Placeholder."""
        self.commands = commands if commands is not None else []
        self.command_helper = WatchguardCommandGeneratorHelper()

    def add_rule(self, rule: Rule) -> None:
        """Generate commands to add a rule.

        Args:
            rule (Rule): The rule to add.

        Returns:
            list[str]: A list of generated commands.
        """
        with self.enter_config_context(), self.enter_policy_context(), self.enter_rule_context(rule.identifier):
            self.commands.append(f'policy-type {rule.packet_filter.identifier} {self.command_helper.build_from(rule)} {self.command_helper.build_to(rule)}')
            if rule.owners:
                self.commands.append(f'policy-tag {self.command_helper.build_owners(rule.owners)}')
            self.commands.append('apply')

    def delete_rule(self, name: str) -> None:
        """Generate command to delete a rule.

        Args:
            name (str): Rule name to delete.

        Returns:
            str: A generated command.
        """
        with self.enter_config_context(), self.enter_policy_context():
            self.commands.append(f'no rule {name}')

    def read_rules(self) -> None:
        """Generate command to read all rules.

        Returns:
            str: A generated command.
        """
        self.commands.append('show rule')

    def read_owners(self) -> None:
        """Generate command to read tags.

        Returns:
            str: A generated command.
        """
        self.commands.append('show policy-tag')

    def read_rule(self, name: str) -> None:
        """Generate command to read a specific rule.

        Args:
            name (str): Rule name to read.

        Returns:
            str: A generated command.
        """
        self.commands.append(f'show rule {name}')

    def add_owner(self, owner: Owner) -> None:
        """Generate commands to add a owner tags.

        Args:
            owner (Owner): Owner object to be added.

        Returns:
            list[str]: A list of generated commands.
        """
        with self.enter_config_context(), self.enter_policy_context():
            policy_tag_commands = [f'policy-tag {owner.identifier} color 0xc0c0c0']
            self.commands.extend(policy_tag_commands)

    def delete_owner(self, owner: str) -> None:
        """Generate commands to add a owner tags.

        Args:
            owner (str): Name of owner tags.

        Returns:
            list[str]: A list of generated commands.
        """
        with self.enter_config_context(), self.enter_policy_context():
            policy_tag_commands = f'no policy-tag {owner}'
            self.commands.extend(policy_tag_commands)

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """Generate commands to add a filter.

        Args:
            packet_filter (PacketFilter): The filter to be added.

        Returns:
            list[str]: A list of generated commands.
        """
        with self.enter_config_context(), self.enter_policy_context():
            policy_type_commands = [f'policy-type {packet_filter.identifier} {self.command_helper.build_service(service)}' for service in packet_filter.root]
            self.commands.extend(policy_type_commands)
            self.commands.append('apply')

    def delete_filter(self, name: str) -> None:
        """Generate command to delete a filter.

        Args:
            name (str): Name of the filter to delete.

        Returns:
            list[str]: A list of generated commands.
        """
        with self.enter_config_context(), self.enter_policy_context():
            self.commands.append(f'no policy-type {name}')

    def read_filters(self) -> None:
        """Generate command to list managed filters.

        Returns:
            str: A generated command.
        """
        self.commands.append('show policy-type')

    def read_filter(self, name: str) -> None:
        """Generate command to read a specific filter.

        Args:
            name (str): Name of the filter.

        Returns:
            str: A generated command.
        """
        self.commands.append(f'show policy-type {name}')

    def get_commands(self) -> list[str]:
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

    @staticmethod
    def build_network(networks: tuple[NetworkPeer, ...]) -> str:
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
            parts.append(f'port-range {service.port_low} {service.port_high}')
        return ' '.join(parts)

    @staticmethod
    def build_from(rule: Rule) -> str:
        """Build the 'from' part of a rule command.

        Args:
            rule (Rule): Rule with source definitions.

        Returns:
            str: A command-ready source string.
        """
        return f'from {WatchguardCommandGeneratorHelper.build_network(rule.sources)}'

    @staticmethod
    def build_to(rule: Rule) -> str:
        """Build the 'to' part of a rule command.

        Args:
            rule (Rule): Rule with destination definitions.

        Returns:
            str: A command-ready destination string.
        """
        return f'to {WatchguardCommandGeneratorHelper.build_network(rule.destinations)}'

    @staticmethod
    def build_owners(owners: tuple[Owner, ...]) -> str:
        """Build the owners part of a rule command.

        Args:
            owners (tuple[str, ...]): List-like touple of owner tags.

        Returns:
            str: A string with owner tags.
        """
        owners_identifiers = [owner.identifier for owner in owners]
        return ' '.join(owners_identifiers)
