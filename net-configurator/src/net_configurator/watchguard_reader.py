class WatchguardReader(Protocol):
    """Interface with methods for reading."""

    def __enter__(self) -> None:
        """Enter method for context manager."""
        executor.enter()

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_tb: TracebackType | None) -> None:
        """Exit method for context manager."""
        executor.exit()

    def open(self) -> None:
        """Opens reader."""
        executor.connect()

    def close(self) -> None:
        """Closes reader."""
        executor.disconnect()

    def read_all_rules(self) -> list[Any]:
        """read_all_rules stub."""
        command_generator.read_all_rules()
        parse
        for rule in rules
            executor.execute(command)
            parse

    def read_all_filters(self) -> list[Any]:
        """read_all_filters stub."""
        command_generator.read_all_filters()
        parse
        for rule in rules
            executor.execute(command)
            parse

    def read_all_owners(self) -> list[str]:
        """read_all_owners stub."""
        command_generator.read_all_owners()
        executor.execute(command)
        parse
        

