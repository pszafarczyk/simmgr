"""Reader/writer classes for Watchguard routers."""

import logging
from typing import Any

from net_configurator.logg_sensitive_info_filter import redact_sensitive_info
from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule
from net_configurator.watchguard_command_builder import WatchguardCommandBuilder
from net_configurator.watchguard_parser import WatchguardParser
from net_configurator.watchguard_reader import WatchguardReader


class WatchguardReaderWriter(WatchguardReader):
    """Interface with methods for reading and writing."""

    def __init__(self, device_config: dict[str, Any]) -> None:
        """Initialize WatchguardReaderWriter with device config and logger.

        Args:
            device_config (dict): Dictionary containing connection parameters.
            The supported keys include:
                ip (str): IP address of the device.
                host (str): Hostname of the device.
                username (str): Username for authentication.
                password (Optional[str]): Password for authentication.
                secret (str): Enable/privileged mode password.
                port (Optional[int]): SSH or Telnet port to use.
                device_type (str): Type of device (e.g., 'watchguard_fireware').
                global_delay_factor (float): Global delay factor for command execution.
                use_keys (bool): Whether to use SSH keys.
                key_file (Optional[str]): Path to private key file.
                passphrase (Optional[str]): Passphrase for encrypted private key.
        """
        self.__logger = logging.getLogger(self.__class__.__name__)
        self.__logger.debug('Initializing WatchguardReaderWriter with device config: %s', redact_sensitive_info(device_config))
        super().__init__(device_config)
        self.__logger.info('WatchguardReaderWriter initialized successfully')

    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the device.

        Args:
            rule (Rule): The rule to add.
        """
        self.__logger.debug('Adding rule: %s', rule.identifier)
        command_generator = WatchguardCommandBuilder()
        parse = WatchguardParser()

        command_generator.add_rule(rule)
        commands = command_generator.build()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)
        self.__logger.info('Successfully added rule: %s', rule.identifier)

    def delete_rule(self, rule_identifier: str) -> None:
        """Delete a rule from the device.

        Args:
            rule_identifier (str): Identifier of the rule to delete.
        """
        self.__logger.debug('Deleting rule: %s', rule_identifier)
        command_generator = WatchguardCommandBuilder()
        parse = WatchguardParser()

        command_generator.delete_rule(rule_identifier)
        commands = command_generator.build()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)
        self.__logger.info('Successfully deleted rule: %s', rule_identifier)

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """Add a filter to the device.

        Args:
            packet_filter (PacketFilter): The filter to add.
        """
        self.__logger.debug('Adding filter: %s', packet_filter.identifier)
        command_generator = WatchguardCommandBuilder()
        parse = WatchguardParser()

        command_generator.add_filter(packet_filter)
        commands = command_generator.build()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)
        self.__logger.info('Successfully added filter: %s', packet_filter.identifier)

    def delete_filter(self, filter_identifier: str) -> None:
        """Delete a filter from the device.

        Args:
            filter_identifier (str): Identifier of the filter to delete.
        """
        self.__logger.debug('Deleting filter: %s', filter_identifier)
        command_generator = WatchguardCommandBuilder()
        parse = WatchguardParser()

        command_generator.delete_filter(filter_identifier)
        commands = command_generator.build()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)
        self.__logger.info('Successfully deleted filter: %s', filter_identifier)

    def add_owner(self, owner: Owner) -> None:
        """Add an owner to the device.

        Args:
            owner (Owner): The owner to add.
        """
        self.__logger.debug('Adding owner: %s', owner.identifier)
        command_generator = WatchguardCommandBuilder()
        parse = WatchguardParser()

        command_generator.add_owner(owner)
        commands = command_generator.build()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)
        self.__logger.info('Successfully added owner: %s', owner.identifier)

    def delete_owner(self, owner_identifier: str) -> None:
        """Delete an owner from the device.

        Args:
            owner_identifier (str): Identifier of the owner to delete.
        """
        self.__logger.debug('Deleting owner: %s', owner_identifier)
        command_generator = WatchguardCommandBuilder()
        parse = WatchguardParser()

        command_generator.delete_owner(owner_identifier)
        commands = command_generator.build()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)
        self.__logger.info('Successfully deleted owner: %s', owner_identifier)

    def apply_changes(self) -> None:
        """Apply changes to the device."""
        self.__logger.debug('Applying changes')
        self.__logger.info('Changes applied successfully')


class WatchguardReaderWriterFactory:
    """Factory creating WatchguardReaderWriter."""

    def __init__(self, device_cfg: dict[str, Any]) -> None:
        """Sets the device configuration.

        Args:
            device_cfg (dict): Dictionary containing connection parameters.
            The supported keys include:
                ip (str): IP address of the device.
                host (str): Hostname of the device.
                username (str): Username for authentication.
                password (Optional[str]): Password for authentication.
                secret (str): Enable/privileged mode password.
                port (Optional[int]): SSH or Telnet port to use.
                device_type (str): Type of device (e.g., 'watchguard_fireware').
                global_delay_factor (float): Global delay factor for command execution.
                use_keys (bool): Whether to use SSH keys.
                key_file (Optional[str]): Path to private key file.
                passphrase (Optional[str]): Passphrase for encrypted private key.
        """
        self.__logger = logging.getLogger(self.__class__.__name__)
        self.__logger.debug('Initializing WatchguardReaderWriterFactory with device config: %s', redact_sensitive_info(device_cfg))
        self.__device_cfg = device_cfg
        self.__logger.debug('WatchguardReaderWriterFactory initialized')

    def create(self) -> WatchguardReaderWriter:
        """Create ReaderWriter for Watchguard."""
        self.__logger.debug('Creating WatchguardReaderWriter instance')
        reader_writer = WatchguardReaderWriter(self.__device_cfg)
        self.__logger.info('WatchguardReaderWriter instance created')
        return reader_writer
