class WatchguardReaderWriter(WatchguardReader):
    """Interface with methods for reading and writing."""

    def add_rule(self, rule: Rule) -> None:
        """add_rule stub."""
        generate_command 
        get_command
        execute

    def delete_rule(self, rule_identifier: str) -> None:
        """delete_rule stub."""
        generate_command
        get_command
        execute

    def add_filter(self, packet_filter: PacketFilter) -> None:
        """add_filter stub."""
        generate_command
        get_command
        execute

    def delete_filter(self, filter_identifier: str) -> None:
        """delete_filter stub."""
        generate_command
        get_command
        execute

    def add_owner(self, owner: Owner) -> None:
        """add_owner stub."""
        generate_command
        get_command
        execute

    def delete_owner(self, owner_identifier: str) -> None:
        """delete_owner stub."""
        generate_command
        get_command
        execute

    def apply_changes(self) -> None:
        """apply_changes stub."""
        pass
