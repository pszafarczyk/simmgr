class WatchguardReader():
    """Interface with methods for reading."""
    
    def __init__(self, device_config: dict[str, Any]) -> None:
        """Initialize the Executor and connect to the device.

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
        self.executor = Executor(device_config)

    def __enter__(self) -> None:
        """Enter method for context manager."""
        self.__executor.__enter__()

    def __exit__(self, exc_type: type[BaseException] | None, exc_value: BaseException | None, exc_tb: TracebackType | None) -> None:
        """Exit method for context manager."""
        self.executor.__exit__(exc_type, exc_value, exc_tb)

    def open(self) -> None:
        """Opens reader."""
        self.executor.connect()

    def close(self) -> None:
        """Closes reader."""
        self.executor.disconnect()

    def read_all_rules(self) -> list[Any]:
        """read_all_rules stub."""
        rules = []

        self.command_generator.read_rules()
        command = self.get_commands()
        response = executor.execute(command)
        rules = parse.extract_rule_names(response)
        for rule in rules
            command = self.command_generator.read_rule(rule)
            response = executor.execute(command)
            rules.append(parse.parse_rule(response))

    def read_all_filters(self) -> list[Any]:
        """read_all_filters stub."""
        filters = []

        self.command_generator.read_filters()
        command = self.get_commands()
        response = executor.execute(command)
        rules = parse.extract_filter_names(response)
        for rule in rules
            command = self.command_generator.read_filter(rule)
            response = executor.execute(command)
            filters.append(parse.parse_filter(response))

    def read_all_owners(self) -> list[str]:
        """read_all_owners stub."""
        command = command_generator.read_all_owners()
        response = executor.execute(command)
        owners = parse.extract_owner_names(response)    
