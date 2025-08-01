from typing import Any
from types import TracebackType

from net_configurator.executor import Executor
from net_configurator.watchguard_command_builder import WatchguardCommandBuilder
from net_configurator.watchguard_parser import WatchguardParser
from net_configurator.logg_sensitive_info_filter import redact_sensitive_info

import logging


class WatchguardReader:
    """Interface with methods for reading."""

    def __init__(self, device_config: dict[str, Any]) -> None:
        """Initialize the _executor.

        Args:
            device_config (dict): Dictionary containing connection parameters.
            The supported keys include:
                ip (str): IP address of the device.
                host (str): Hostname of the device.
                username (str): Username for authentication.
                password (Optional[str]): Password for authentication.
                secret (str): Enable/privileged mode password.
                port (Optional[int]): SSH or Telnet port to use.
                device_type (str): Type of device (e.g.,watchguard_fireware').
                global_delay_factor (float): Global delay factor for command execution.
                use_keys (bool): Whether to use SSH keys.
                key_file (Optional[str]): Path to private key file.
                passphrase (Optional[str]): Passphrase for encrypted private key.
        """
        self.__logger = logging.getLogger(self.__class__.__name__)
        self.__logger.debug('Initializing WatchguardReader with device config: %s', redact_sensitive_info(device_config))
        self._executor = Executor(device_config)
        self.__logger.debug('WatchguardReader initialized')

    def __enter__(self) -> None:
        """Enter method for context manager."""
        self.__logger.debug('Entering WatchguardReader context')
        self._executor.__enter__()
        self.__logger.debug('WatchguardReader context entered')

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_tb: TracebackType | None) -> None:
        """Exit method for context manager."""
        self.__logger.debug('Exiting WatchguardReader context')
        self._executor.__exit__(exc_type, exc_value, exc_tb)
        self.__logger.debug('WatchguardReader context exited')

    def open(self) -> None:
        """Opens reader."""
        self.__logger.debug('Opening WatchguardReader connection')
        self._executor.connect()
        self.__logger.info('WatchguardReader connection opened')

    def close(self) -> None:
        """Closes reader."""
        self.__logger.debug('Closing WatchguardReader connection')
        self._executor.disconnect()
        self.__logger.info('WatchguardReader connection closed')

    def read_all_rules(self) -> list[Any]:
        """Read all rules from the device."""
        self.__logger.debug('Reading all rules')
        rules_without_filters = []
        rule_names = []
        rules = []
        command_generator = WatchguardCommandBuilder()
        parse = WatchguardParser()

        command_generator.read_rules()
        commands = command_generator.build()
        for command in commands:
            self.__logger.debug('Executing command: %s', command)
            response = self._executor.execute(command)
            rule_names = parse.extract_rule_names(response)
            self.__logger.info('Extracted %d rule names', len(rule_names))

        for rule in rule_names:
            command_generator = WatchguardCommandBuilder()
            command_generator.read_rule(rule)
            command = command_generator.build()
            self.__logger.debug('Executing rule read command for rule: %s', rule)
            response = self._executor.execute(command[0])
            rule_attributes = parse.parse_rule(response)
            rules_without_filters.append(rule_attributes)
            self.__logger.debug('Parsed rule: %s', rule)

        for rule in rules_without_filters:
            command_generator = WatchguardCommandBuilder()
            command_generator.read_filter(rule.filter_name)
            response = self._executor.execute(command_generator.build()[0])
            packet_filter = parse.parse_filter(response)
            rule_to_append = rule
            rule_to_append.packet_filter = packet_filter
            rules.append(rule_to_append.to_dict())
            self.__logger.debug('Appended rule with filter: %s', rule.filter_name)

        self.__logger.info('Successfully read %d rules', len(rules))
        return rules

    def read_all_filters(self) -> list[Any]:
        """Read all filters from the device."""
        self.__logger.debug('Reading all filters')
        packet_filter_names = []
        packet_filters = []
        command_generator = WatchguardCommandBuilder()
        parse = WatchguardParser()

        command_generator.read_filters()
        command = command_generator.build()
        self.__logger.debug('Executing read filters command: %s', command)
        response = self._executor.execute(command[0])
        packet_filter_names = parse.extract_filter_names(response)
        self.__logger.info('Extracted %d filter names', len(packet_filter_names))

        for packet_filter_name in packet_filter_names:
            command_generator = WatchguardCommandBuilder()
            command_generator.read_filter(packet_filter_name)
            command = command_generator.build()
            self.__logger.debug('Executing read filter command for filter: %s', packet_filter_name)
            response = self._executor.execute(command[0])
            filter_obj = parse.parse_filter(response)
            packet_filters.append(filter_obj)
            self.__logger.debug('Parsed filter: %s', packet_filter_name)

        self.__logger.info('Successfully read %d filters', len(packet_filters))
        return packet_filters

    def read_all_owners(self) -> list[str]:
        """Read all owners from the device."""
        self.__logger.debug('Reading all owners')
        command_generator = WatchguardCommandBuilder()
        parse = WatchguardParser()

        command_generator.read_owners()
        command = command_generator.build()
        self.__logger.debug('Executing read owners command: %s', command)
        response = self._executor.execute(command[0])
        owners = parse.extract_owner_names(response)
        self.__logger.info('Successfully read %d owners', len(owners))
        return owners


class WatchguardReaderFactory:
    """Factory creating WatchguardReader."""

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
        self.__logger.debug('Initializing WatchguardReaderFactory with device config: %s', redact_sensitive_info(device_cfg))
        self.__device_cfg = device_cfg
        self.__logger.debug('WatchguardReaderFactory initialized')

    def create(self) -> WatchguardReader:
        """Create Reader for Watchguard."""
        self.__logger.debug('Creating WatchguardReader instance')
        reader = WatchguardReader(self.__device_cfg)
        self.__logger.info('WatchguardReader instance created')
        return reader
