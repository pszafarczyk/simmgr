from typing import Any
from types import TracebackType

from net_configurator.executor import Executor
from net_configurator.watchguard_command_generator import WatchguardCommandGenerator
from net_configurator.watchguard_parser import WatchguardParser


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
        self._executor = Executor(device_config)

    def __enter__(self) -> None:
        """Enter method for context manager."""
        self._executor.__enter__()

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_tb: TracebackType | None) -> None:
        """Exit method for context manager."""
        self._executor.__exit__(exc_type, exc_value, exc_tb)

    def open(self) -> None:
        """Opens reader."""
        self._executor.connect()

    def close(self) -> None:
        """Closes reader."""
        self._executor.disconnect()

    def read_all_rules(self) -> list[Any]:
        """read_all_rules stub."""
        rules_without_filters = []
        rule_names = []
        rules = []
        command_generator = WatchguardCommandGenerator()
        parse = WatchguardParser()

        command_generator.read_rules()
        commands = command_generator.get_commands()
        for command in commands:
            response = self._executor.execute(command)
            rule_names = parse.extract_rule_names(response)

        for rule in rule_names:
            command_generator = WatchguardCommandGenerator()
            command_generator.read_rule(rule)
            command = command_generator.get_commands()
            response = self._executor.execute(command[0])
            rules_without_filters.append(parse.parse_rule(response))

        for rule in rules_without_filters:
            command_generator = WatchguardCommandGenerator()
            command_generator.read_filter(rule.filter_name)
            response = self._executor.execute(command_generator.get_commands()[0])
            packet_filter = parse.parse_filter(response)
            rule_to_append = rule
            rule_to_append.packet_filter = packet_filter
            rules.append(rule_to_append.to_dict())

        return rules

    def read_all_filters(self) -> list[Any]:
        """read_all_filters stub."""
        packet_filter_names = []
        packet_filters = []
        command_generator = WatchguardCommandGenerator()
        parse = WatchguardParser()

        command_generator.read_filters()
        command = command_generator.get_commands()
        response = self._executor.execute(command[0])
        packet_filter_names = parse.extract_filter_names(response)
        for packet_filter_name in packet_filter_names:
            command_generator = WatchguardCommandGenerator()
            command_generator.read_filter(packet_filter_name)
            command = command_generator.get_commands()
            response = self._executor.execute(command[0])
            filter_obj = parse.parse_filter(response)
            packet_filters.append(filter_obj)

        return packet_filters

    def read_all_owners(self) -> list[str]:
        """read_all_owners stub."""
        """read_all_filters stub."""
        command_generator = WatchguardCommandGenerator()
        parse = WatchguardParser()

        command_generator.read_owners()
        command = command_generator.get_commands()
        response = self._executor.execute(command[0])
        return parse.extract_owner_names(response)


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
                device_type (str): Type of device (e.g.,watchguard_fireware').
                global_delay_factor (float): Global delay factor for command execution.
                use_keys (bool): Whether to use SSH keys.
                key_file (Optional[str]): Path to private key file.
                passphrase (Optional[str]): Passphrase for encrypted private key.
        """
        self.__device_cfg = device_cfg

    def create(self) -> WatchguardReader:
        """Create Reader for Watchguard."""
        return WatchguardReader(self.__device_cfg)
