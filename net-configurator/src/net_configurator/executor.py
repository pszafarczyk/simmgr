"""Classes for executing commands on the firewall."""

from typing import Any
from typing import cast

from netmiko import BaseConnection
from netmiko import ConnectHandler
from netmiko import NetmikoAuthenticationException
from netmiko import NetmikoBaseException
from netmiko import NetmikoTimeoutException
from tenacity import retry
from tenacity import RetryError
from tenacity import stop_after_delay
from tenacity import wait_fixed


class ExecutorBaseError(Exception):
    """Base class for Executor-related errors."""


class ExecutorConnectionTimeoutError(ExecutorBaseError):
    """Raised when connection attempt times out."""


class ExecutorAuthenticationError(ExecutorBaseError):
    """Raised when authentication fails."""


class ExecutorSocketError(ExecutorBaseError):
    """Raised when a socket error occurs during connection."""


class ExecutorDisconnectTimeoutError(ExecutorBaseError):
    """Raised when disconnection attempt times out."""

    def __init__(self, message: str = 'Failed to disconnect within timeout period', retries: int = 20):
        """Initialize the exception with a message and retry count.

        Args:
            message (str): The error message. Defaults to
                "Failed to disconnect within timeout period".
            retries (int): Number of retry attempts. Defaults to 20.
        """
        self.retries = retries
        super().__init__(message)


class NoConnectionError(ExecutorBaseError):
    """Raised when attempting to execute a command without an active connection."""


class ExecuteError(ExecutorBaseError):
    """Raised when command execution fails."""


class Executor:
    """Executor for managing SSH connections and executing commands."""

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
                device_type (str): Type of device (e.g., 'watchguard_fireware').
                global_delay_factor (float): Global delay factor for command execution.
                use_keys (bool): Whether to use SSH keys.
                key_file (Optional[str]): Path to private key file.
                passphrase (Optional[str]): Passphrase for encrypted private key.
        """
        self.__device = device_config
        self.__connection: BaseConnection | None = None

    def __enter__(self) -> 'Executor':
        """Enter the runtime context related to this object."""
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the runtime context and disconnect from the device."""
        self.disconnect()

    def connect(self) -> None:
        """Establish connection.

        Raises:
            ExecutorConnectionTimeoutError: If connection fails due to timeout.
            ExecutorAuthenticationError: If authentication fails.
            ExecutorSocketError: If a socket error occurs during connection.
        """
        connection_timeout_msg = 'Connection timed out'
        authentication_failed_msg = 'Authentication failed'
        socket_error_msg = 'Socket error during connection'

        if not self.is_connected():
            try:
                self.__connection = cast(BaseConnection, ConnectHandler(**self.__device))
            except NetmikoTimeoutException as err:
                raise ExecutorConnectionTimeoutError(connection_timeout_msg) from err
            except NetmikoAuthenticationException as err:
                raise ExecutorAuthenticationError(authentication_failed_msg) from err
            except OSError as err:
                raise ExecutorSocketError(socket_error_msg) from err
        else:
            print('Warning: Already connected to the device')

    def disconnect(self) -> None:
        """Send 'exit' and wait until the connection is closed.

        Raises:
            ExecutorDisconnectTimeoutError: If connection doesn't close
                within expected time.
        """
        if self.is_connected():
            try:
                self._try_disconnect()
            except RetryError as err:
                raise ExecutorDisconnectTimeoutError(retries=20) from err
            self.__connection = None

    def _send_command(self, command: str, expect_output: str = '.*WG[a-zA-Z()/]*#$') -> str:
        """Wrapper for Netmiko send_command.

        Args:
            command (str): Command to send.
            expect_output (str): Regular expression for determining output end.

        Returns:
            str: Netmiko send_command output as str.

        Raises:
            ExecuteError: If command execution fails.
        """
        execute_error_msg = f'Failed to execute command: {command}'
        try:
            return cast(str, self.__connection.send_command(command, expect_string=expect_output))  # type: ignore[union-attr]
        except NetmikoBaseException as err:
            raise ExecuteError(execute_error_msg) from err

    def is_connected(self) -> bool:
        """Check if there is connection."""
        return isinstance(self.__connection, BaseConnection) and self.__connection.is_alive()

    @retry(stop=stop_after_delay(10), wait=wait_fixed(0.5))
    def _try_disconnect(self) -> None:
        """Retry until connection is inactive.

        Raises:
            ExecutorDisconnectTimeoutError: If connection remains active
                after retry period.
        """
        disconnect_error_msg = 'Connection still active after exit command'
        self._send_command('exit', expect_output='')
        if self.is_connected():
            raise ExecutorDisconnectTimeoutError(disconnect_error_msg)

    def execute(self, command: str) -> str:
        """Execute command and return output as str.

        Args:
            command (str): Command to execute on device.

        Returns:
            str: Output from the executed command.

        Raises:
            NoConnectionError: If there is no active connection to device.
            ExecuteError: If command fails to execute properly.
        """
        no_connection_msg = 'No active connection to device'
        if self.is_connected():
            return self._send_command(command)
        raise NoConnectionError(no_connection_msg)
