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

    def __init__(self, message: str = 'Executor encountered an error') -> None:
        """Initialize base Executor exception."""
        super().__init__(message)


class ExecutorConnectionError(ExecutorBaseError):
    """Raised when SSH connection cannot be established."""

    def __init__(self) -> None:
        """Initialize SSH connection error."""
        super().__init__('Cannot connect to device. There may be no network or the parameters are incorrect.')


class ConnectionTimeoutError(ExecutorBaseError):
    """Raised when SSH connection cannot be established due to timeout."""

    def __init__(self) -> None:
        """Initialize SSH connection timeout error."""
        super().__init__('Cannot connect to device. There may be no network or the parameters are incorrect.')


class AuthenticationError(ExecutorBaseError):
    """Raised when SSH connection cannot be established due to authentication error."""

    def __init__(self) -> None:
        """Initialize SSH connection authentication error."""
        super().__init__('Cannot connect to device due to authentication problem.')


class DisconnectTimeoutError(ExecutorBaseError):
    """Raised when SSH connection does not close within expected time."""

    def __init__(self, retries: int | None = None) -> None:
        """Initialize SSH disconnect timeout error."""
        message = f'SSH connection did not close in time after {retries} retries.'
        super().__init__(message)
        self.retries = retries


class NoConnectionError(ExecutorBaseError):
    """Raised when the connection is still active after 'exit' was sent."""

    def __init__(self) -> None:
        """Initialize still-connected error."""
        super().__init__('There is no connection.')


class ExecuteError(ExecutorBaseError):
    """Raised when the command didn't produce expected effect."""

    def __init__(self) -> None:
        """Initialize execut error."""
        super().__init__('Command failed.')


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
                device_type (str): Type of device (e.g.,watchguard_fireware').
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
            ConnectionTimeoutError: If connection fails due to timeout.
            AuthenticationError: If connection fails due to authentication error.
        """
        if not self.is_connected():
            try:
                self.__connection = cast(BaseConnection, ConnectHandler(**self.__device))
            except NetmikoTimeoutException as err:
                raise ConnectionTimeoutError from err
            except NetmikoAuthenticationException as err:
                raise AuthenticationError from err
            except NetmikoBaseException as err:
                raise ExecutorConnectionError from err

    def disconnect(self) -> None:
        """Send 'exit' and wait until the connection is closed.

        Raises:
            DisconnectTimeoutError: If connection does't close within expected time.
        """
        if self.is_connected():
            try:
                self._send_command('exit', expect_output='')
                self._wait_for_disconnect()
            except RetryError as err:
                raise DisconnectTimeoutError(retries=20) from err
        self.__connection = None

    def _send_command(self, command: str, expect_output: str = '.*WG[a-zA-Z()/]*#$') -> str:
        """Wrapper for Netmiko send_command.

        Args:
            command (str): Command to send.
            expect_output (str): Regular expression for determining output end.

        Returns:
            str: Netmikos send_command output as str.
        """
        return cast(str, self.__connection.send_command(command, expect_string=expect_output))  # type: ignore[union-attr]

    def is_connected(self) -> bool:
        """Check if there is connection."""
        return isinstance(self.__connection, BaseConnection) and self.__connection.is_alive()

    @retry(stop=stop_after_delay(10), wait=wait_fixed(0.5))
    def _wait_for_disconnect(self) -> None:
        """Retry until connection is inactive.

        Raises:
            DisconnectTimeoutError: If connection remains active after retry period.
        """
        if self.is_connected():
            raise DisconnectTimeoutError

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
        if self.is_connected():
            try:
                return self._send_command(command)
            except NetmikoBaseException as err:
                raise ExecuteError from err
        else:
            raise NoConnectionError
