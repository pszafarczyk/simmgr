class WatchguardReaderWriter(WatchguardReader):
    """Interface with methods for reading and writing."""

    def add_rule(self, rule: Rule) -> None:
        """add_rule stub."""
        command_generator.add_rule(rule)
        command = command_generator.get_commands()
        response = self.executor.execute(command)
        #parse.check_for_error(response)

    def delete_rule(self, rule_identifier: str) -> None:
        """delete_rule stub."""
        command_generator.delete_rule(rule_identifier)
        command = command_generator.get_commands()
        response = executor.execute(command)
        #parse.check_for_error(response)

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """add_filter stub."""
        command_generator.add_filter(packet_filter)
        command = command_generator.get_commands()
        response = executor.execute(command)
        #parse.check_for_error(response)

    def delete_filter(self, filter_identifier: str) -> None:
        """delete_filter stub."""
        command_generator.delete_filter(filter_identifier)
        command = command_generator.get_commands()
        response = executor.execute(command)
        #parse.check_for_error(response)

    def add_owner(self, owner: Owner) -> None:
        """add_owner stub."""
        command_generator.add_owner(owner)
        command = command_generator.get_commands()
        response = executor.execute(command)
        #parse.check_for_error(response)

    def delete_owner(self, owner_identifier: str) -> None:
        """delete_owner stub."""
        command_generator.delete_owner(owner_identifier)
        command = command_generator.get_commands()
        response = executor.execute(command)
        #parse.check_for_error(response)

    def apply_changes(self) -> None:
        """apply_changes stub."""
        pass
