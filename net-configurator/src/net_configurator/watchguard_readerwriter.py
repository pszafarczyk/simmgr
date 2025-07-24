"""Reader/writer for Watchguard routers."""

from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule
from net_configurator.watchguard_command_generator import WatchguardCommandGenerator
from net_configurator.watchguard_parser import WatchguardParser
from net_configurator.watchguard_reader import WatchguardReader


class WatchguardReaderWriter(WatchguardReader):
    """Interface with methods for reading and writing."""

    def add_rule(self, rule: Rule) -> None:
        """add_rule stub."""
        command_generator = WatchguardCommandGenerator()
        parse = WatchguardParser()

        command_generator.add_rule(rule)
        commands = command_generator.get_commands()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)

    def delete_rule(self, rule_identifier: str) -> None:
        """delete_rule stub."""
        command_generator = WatchguardCommandGenerator()
        parse = WatchguardParser()

        command_generator.delete_rule(rule_identifier)
        commands = command_generator.get_commands()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """add_filter stub."""
        command_generator = WatchguardCommandGenerator()
        parse = WatchguardParser()

        command_generator.add_filter(packet_filter)
        commands = command_generator.get_commands()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)

    def delete_filter(self, filter_identifier: str) -> None:
        """delete_filter stub."""
        command_generator = WatchguardCommandGenerator()
        parse = WatchguardParser()

        command_generator.delete_filter(filter_identifier)
        commands = command_generator.get_commands()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)

    def add_owner(self, owner: Owner) -> None:
        """add_owner stub."""
        command_generator = WatchguardCommandGenerator()
        parse = WatchguardParser()

        command_generator.add_owner(owner)
        commands = command_generator.get_commands()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)

    def delete_owner(self, owner_identifier: str) -> None:
        """delete_owner stub."""
        command_generator = WatchguardCommandGenerator()
        parse = WatchguardParser()

        command_generator.delete_owner(owner_identifier)
        commands = command_generator.get_commands()
        for command in commands:
            response = self._executor.execute(command)
            parse.check_for_error(response)

    def apply_changes(self) -> None:
        """apply_changes stub."""
