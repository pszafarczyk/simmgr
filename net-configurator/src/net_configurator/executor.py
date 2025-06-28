"""Classes for executing commands on the firewall."""

from typing import Any

from netmiko import BaseConnection
from netmiko import ConnectHandler
from netmiko import NetmikoTimeoutException
from tenacity import retry
from tenacity import RetryError
from tenacity import stop_after_delay
from tenacity import wait_fixed


class ExecutorBaseError(Exception):
    """Base class for Executor-related errors."""

    def __init__(self, message: str = "Executor encountered an error"):
        """Initialize base Executor exception."""
        super().__init__(message)


class SshConnectionTimeoutError(ExecutorBaseError):
    """Raised when SSH connection cannot be established."""

    def __init__(self):
        """Initialize SSH connection timeout error."""
        super().__init__(
            "Cannot connect to device. There may be no network or the parameters are incorrect."
        )


class SshDisconnectTimeoutError(ExecutorBaseError):
    """Raised when SSH connection does not close within expected time."""

    def __init__(self, retries: int | None = None):
        """Initialize SSH disconnect timeout error."""
        message = f"SSH connection did not close in time after {retries} retries."
        super().__init__(message)
        self.retries = retries


class StillConnectedError(ExecutorBaseError):
    """Raised when the connection is still active after 'exit' was sent."""

    def __init__(self):
        """Initialize still-connected error."""
        super().__init__("Connection still active after sending 'exit'.")

class Executor:
    """Executor for managing SSH connections and executing commands."""

    def __init__(self, device_config: dict):
        """Initialize the Executor and connect to the device."""
        self.__watchguard = device_config
        self.__connection: BaseConnection | None = None
        self.connect()

    def __del__(self):
        """Ensure disconnection when the object is garbage collected."""
        if self.__connection:
            self.__connection.send_command('exit', expect_string='')

    def __enter__(self):
        """Enter the runtime context related to this object."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit the runtime context and disconnect from the device."""
        self.disconnect()

    def connect(self) -> None:
        """Establish connection and store as self.__connection."""
        if self.__connection is None:
            try:
                self.__connection = ConnectHandler(**self.__watchguard)
            except NetmikoTimeoutException as err:
                raise SshConnectionTimeoutError from err

    def disconnect(self):
        """Send 'exit' and wait until the connection is closed."""
        if self.__connection:
            self.__connection.send_command('exit', expect_string='')
            try:
                self._wait_for_disconnect()
            except RetryError as err:
                raise SshDisconnectTimeoutError(retries=20) from err

    @retry(stop=stop_after_delay(10), wait=wait_fixed(0.5))
    def _wait_for_disconnect(self):
        """Retry until connection is inactive."""
        if self.__connection.is_active():
            raise StillConnectedError

    def execute(self, command: str) -> dict[str, Any]:
        """Execute command and return structured output."""
        if self.__connection is None:
            self.connect()
        return self.__connection.send_command(command)
