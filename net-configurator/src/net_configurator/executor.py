"""Classes for executing commands on the firewall."""

import contextlib

from netmiko import BaseConnection
from netmiko import ConnectHandler
from netmiko import NetmikoAuthenticationException
from netmiko import NetmikoTimeoutException
from tenacity import retry
from tenacity import RetryError
from tenacity import stop_after_delay
from tenacity import wait_fixed


class ExecutorBaseError(Exception):
    """Base class for Executor-related errors."""

    def __init__(self, message: str = 'Executor encountered an error'):
        """Initialize base Executor exception."""
        super().__init__(message)


class ConnectionTimeoutError(ExecutorBaseError):
    """Raised when SSH connection cannot be established."""

    def __init__(self):
        """Initialize SSH connection timeout error."""
        super().__init__('Cannot connect to device. There may be no network or the parameters are incorrect.')


class AuthenticationError(ExecutorBaseError):
    """Raised when SSH connection cannot be established."""

    def __init__(self):
        """Initialize SSH connection authentication error."""
        super().__init__('Cannot connect to device due to authentication problem.')


class DisconnectTimeoutError(ExecutorBaseError):
    """Raised when SSH connection does not close within expected time."""

    def __init__(self, retries: int | None = None):
        """Initialize SSH disconnect timeout error."""
        message = f'SSH connection did not close in time after {retries} retries.'
        super().__init__(message)
        self.retries = retries


class NoConnectionError(ExecutorBaseError):
    """Raised when the connection is still active after 'exit' was sent."""

    def __init__(self):
        """Initialize still-connected error."""
        super().__init__('There is no connection.')


class ExecuteError(ExecutorBaseError):
    """Raised when the connection is still active after 'exit' was sent."""

    def __init__(self):
        """Initialize still-connected error."""
        super().__init__('There is no connection.')


class Executor:
    """Executor for managing SSH connections and executing commands."""

    def __init__(self, device_config: dict):
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

    def __del__(self):
        """Ensure disconnection when the object is garbage collected."""
        with contextlib.suppress(Exception):
            self.__connection.send_command('exit', expect_string='')

    def __enter__(self):
        """Enter the runtime context related to this object."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the runtime context and disconnect from the device."""
        self.disconnect()

    def connect(self) -> None:
        """Establish connection."""
        if self.__connection is None:
            try:
                self.__connection = ConnectHandler(**self.__device)
            except NetmikoTimeoutException as err:
                raise ConnectionTimeoutError from err
            except NetmikoAuthenticationException as err:
                raise AuthenticationError from err

    def disconnect(self):
        """Send 'exit' and wait until the connection is closed."""
        if self.__connection:
            self.__connection.send_command('exit', expect_string='')
            try:
                self._wait_for_disconnect()
            except RetryError as err:
                raise DisconnectTimeoutError(retries=20) from err
        self.__connection = None

    @retry(stop=stop_after_delay(10), wait=wait_fixed(0.5))
    def _wait_for_disconnect(self):
        """Retry until connection is inactive."""
        if self.__connection.is_alive():
            raise DisconnectTimeoutError

    def execute(self, command: str) -> str:
        """Execute command and return structured output."""
        if self.__connection is None:
            raise NoConnectionError
        try:
            return self.__connection.send_command(command,expect_string = '#')
        except Exception as err:
            raise ExecuteError from err
