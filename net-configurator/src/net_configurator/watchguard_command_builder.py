"""Classes for generating WatchGuard-specific commands."""

from collections.abc import Iterator
from contextlib import contextmanager
import logging

from net_configurator.rule import NetworkPeer
from net_configurator.rule import NetworkService
from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule


class WatchguardCommandBuilder:
    """WatchGuard-specific command generator."""

    def __init__(self, commands: list[str] | None = None) -> None:
        """Placeholder."""
        self.__logger = logging.getLogger(self.__class__.__name__)
        self.__logger.debug('Initializing WatchguardCommandBuilder')
        self.commands = commands if commands is not None else []
        self.__logger.debug('Command builder initialized with %d commands', len(self.commands))

    def add_rule(self, rule: Rule) -> None:
        """Generate commands to add a rule.

        Args:
            rule (Rule): The rule to add.

        Returns:
            list[str]: A list of generated commands.
        """
        self.__logger.debug('Building commands to add rule: %s', rule.identifier)
        with self.enter_config_context(), self.enter_policy_context(), self.enter_rule_context(rule.identifier):
            self.commands.append(f'policy-type {rule.packet_filter.identifier} {self.__build_from(rule)} {self.__build_to(rule)}')
            if rule.owners:
                self.commands.append(f'policy-tag {self.__build_owners(rule.owners)}')
            self.commands.append('apply')
        self.__logger.info('Added rule commands for rule: %s', rule.identifier)

    def delete_rule(self, name: str) -> None:
        """Generate command to delete a rule.

        Args:
            name (str): Rule name to delete.

        Returns:
            str: A generated command.
        """
        self.__logger.debug('Building command to delete rule: %s', name)
        with self.enter_config_context(), self.enter_policy_context():
            self.commands.append(f'no rule {name}')
            self.commands.append('apply')
        self.__logger.info('Added delete rule command for rule: %s', name)

    def read_rules(self) -> None:
        """Generate command to read all rules."""
        self.__logger.debug('Building command to read all rules')
        self.commands.append('show rule')
        self.__logger.info('Added read all rules command')

    def read_owners(self) -> None:
        """Generate command to read tags."""
        self.__logger.debug('Building command to read all owners')
        self.commands.append('show policy-tag')
        self.__logger.info('Added read all owners command')

    def read_rule(self, name: str) -> None:
        """Generate command to read a specific rule.

        Args:
            name (str): Rule name to read.
        """
        self.__logger.debug('Building command to read rule: %s', name)
        self.commands.append(f'show rule {name}')
        self.__logger.info('Added read rule command for rule: %s', name)

    def add_owner(self, owner: Owner) -> None:
        """Generate commands to add a owner tags.

        Args:
            owner (Owner): Owner object to be added.

        Returns:
            list[str]: A list of generated commands.
        """
        self.__logger.debug('Building commands to add owner: %s', owner.identifier)
        with self.enter_config_context(), self.enter_policy_context():
            policy_tag_commands = f'policy-tag {owner.identifier} color 0xc0c0c0'
            self.commands.append(policy_tag_commands)
            self.commands.append('apply')
        self.__logger.info('Added owner commands for owner: %s', owner.identifier)

    def delete_owner(self, owner: str) -> None:
        """Generate commands to add a owner tags.

        Args:
            owner (str): Name of owner tags.

        Returns:
            list[str]: A list of generated commands.
        """
        self.__logger.debug('Building commands to delete owner: %s', owner)
        with self.enter_config_context(), self.enter_policy_context():
            policy_tag_commands = f'no policy-tag {owner}'
            self.commands.append(policy_tag_commands)
            self.commands.append('apply')
        self.__logger.info('Added delete owner commands for owner: %s', owner)

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """Generate commands to add a filter.

        Args:
            packet_filter (PacketFilter): The filter to be added.

        Returns:
            list[str]: A list of generated commands.
        """
        self.__logger.debug('Building commands to add filter: %s', packet_filter.identifier)
        with self.enter_config_context(), self.enter_policy_context():
            policy_type_commands = [f'policy-type {packet_filter.identifier} {self.__build_service(service)}' for service in packet_filter.services]
            self.commands.extend(policy_type_commands)
            self.commands.append('apply')
        self.__logger.info('Added filter commands for filter: %s', packet_filter.identifier)

    def delete_filter(self, name: str) -> None:
        """Generate command to delete a filter.

        Args:
            name (str): Name of the filter to delete.

        Returns:
            list[str]: A list of generated commands.
        """
        self.__logger.debug('Building command to delete filter: %s', name)
        with self.enter_config_context(), self.enter_policy_context():
            self.commands.append(f'no policy-type {name}')
            self.commands.append('apply')
        self.__logger.info('Added delete filter command for filter: %s', name)

    def read_filters(self) -> None:
        """Generate command to list managed filters."""
        self.__logger.debug('Building command to read all filters')
        self.commands.append('show policy-type')
        self.__logger.info('Added read all filters command')

    def read_filter(self, name: str) -> None:
        """Generate command to read a specific filter.

        Args:
            name (str): Name of the filter.
        """
        self.__logger.debug('Building command to read filter: %s', name)
        self.commands.append(f'show policy-type {name}')
        self.__logger.info('Added read filter command for filter: %s', name)

    def build(self) -> list[str]:
        """Return the list of generated commands."""
        self.__logger.debug('Building final command list with %d commands', len(self.commands))
        return self.commands

    @contextmanager
    def enter_config_context(self) -> Iterator[None]:
        """Context manager to open and close a config block."""
        self.__logger.debug('Entering config context')
        self.commands.append('config')
        try:
            yield
        finally:
            self.commands.append('exit')
            self.__logger.debug('Exiting config context')

    @contextmanager
    def enter_policy_context(self) -> Iterator[None]:
        """Context manager to open and close a policy block."""
        self.__logger.debug('Entering policy context')
        self.commands.append('policy')
        try:
            yield
        finally:
            self.commands.append('exit')
            self.__logger.debug('Exiting policy context')

    @contextmanager
    def enter_rule_context(self, name: str) -> Iterator[None]:
        """Context manager to define a rule block.

        Args:
            name (str): Rule name.
        """
        self.__logger.debug('Entering rule context for rule: %s', name)
        self.commands.append(f'rule {name}')
        try:
            yield
        finally:
            self.commands.append('exit')
            self.__logger.debug('Exiting rule context for rule: %s', name)

    @contextmanager
    def enter_filter_context(self, name: str) -> Iterator[None]:
        """Context manager to define a filter block.

        Args:
            name (str): Filter name.
        """
        self.__logger.debug('Entering filter context for filter: %s', name)
        self.commands.append(f'policy-type {name}')
        try:
            yield
        finally:
            self.commands.append('exit')
            self.__logger.debug('Exiting filter context for filter: %s', name)

    def __build_network(self, networks: tuple[NetworkPeer, ...]) -> str:
        """Build network string from a list of NetworkPeer objects.

        Args:
            networks (tuple[NetworkPeer, ...]): Tuple of networks.

        Returns:
            str: A command-ready network string.
        """
        self.__logger.debug('Building network string for %d networks', len(networks))
        parts = []
        for network in networks:
            if network.is_address_single():
                parts.append(f'host-ip {network.ip_low}')
                self.__logger.debug('Added single address: %s', network.ip_low)
            elif network.is_address_range():
                parts.append(f'host-range {network.ip_low} {network.ip_high}')
                self.__logger.debug('Added address range: %s - %s', network.ip_low, network.ip_high)
            else:
                parts.append(f'network-ip {network.ip_low}')
                self.__logger.debug('Added network IP: %s', network.ip_low)
        result = ' '.join(parts)
        self.__logger.debug('Built network string: %s', result)
        return result

    def __build_service(self, service: NetworkService) -> str:
        """Build service string from a NetworkService object.

        Args:
            service (NetworkService): A service to describe.

        Returns:
            str: A command-ready service string.
        """
        self.__logger.debug('Building service string for protocol: %s', service.protocol)
        parts = [f'protocol {service.protocol}']
        if service.protocol == 'icmp':
            parts.append('Any 255')
            self.__logger.debug('Added ICMP service: Any 255')
        elif service.is_port_single():
            parts.append(f'{service.port_low}')
            self.__logger.debug('Added single port: %s', service.port_low)
        else:
            parts.append(f'port-range {service.port_low} {service.port_high}')
            self.__logger.debug('Added port range: %s - %s', service.port_low, service.port_high)
        result = ' '.join(parts)
        self.__logger.debug('Built service string: %s', result)
        return result

    def __build_from(self, rule: Rule) -> str:
        """Build the 'from' part of a rule command.

        Args:
            rule (Rule): Rule with source definitions.

        Returns:
            str: A command-ready source string.
        """
        self.__logger.debug('Building "from" part for rule: %s', rule.identifier)
        result = f'from {self.__build_network(rule.sources)}'
        self.__logger.debug('Built "from" string: %s', result)
        return result

    def __build_to(self, rule: Rule) -> str:
        """Build the 'to' part of a rule command.

        Args:
            rule (Rule): Rule with destination definitions.

        Returns:
            str: A command-ready destination string.
        """
        self.__logger.debug('Building "to" part for rule: %s', rule.identifier)
        result = f'to {self.__build_network(rule.destinations)}'
        self.__logger.debug('Built "to" string: %s', result)
        return result

    def __build_owners(self, owners: tuple[Owner, ...]) -> str:
        """Build the owners part of a rule command.

        Args:
            owners (tuple[Owner, ...]): Tuple of owner tags.

        Returns:
            str: A string with owner tags.
        """
        self.__logger.debug('Building owners string for %d owners', len(owners))
        owners_identifiers = [owner.identifier for owner in owners]
        result = ' '.join(owners_identifiers)
        self.__logger.debug('Built owners string: %s', result)
        return result
