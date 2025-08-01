"""Classes for executing commands on the firewall."""

import logging
from typing import Any
from typing import cast

from netmiko import BaseConnection
from netmiko import ConnectHandler
from netmiko import NetmikoAuthenticationException
from netmiko import NetmikoBaseException
from netmiko import NetmikoTimeoutException
from tenacity import retry
from tenacity import RetryError
from tenacity import stop_after_attempt
from tenacity import wait_fixed


SENSITIVE_KEYS = {'password', 'secret', 'passphrase'}


class ExecutorBaseError(Exception):
    """Base class for Executor-related errors."""

    pass


class ExecutorConnectionTimeoutError(ExecutorBaseError):
    """Raised when connection attempt times out."""

    pass


class ExecutorAuthenticationError(ExecutorBaseError):
    """Raised when authentication fails."""

    pass


class ExecutorSocketError(ExecutorBaseError):
    """Raised when a socket error occurs during connection."""

    pass


class ExecutorDisconnectTimeoutError(ExecutorBaseError):
    """Raised when disconnection attempt times out."""

    def __init__(self, message: str = 'Failed to disconnect within timeout period', retries: int = 10):
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

    pass


class ExecuteError(ExecutorBaseError):
    """Raised when command execution fails."""

    pass


def redact_sensitive_info(config):
    return {k: ('***REDACTED***' if k.lower() in SENSITIVE_KEYS else v) for k, v in config.items()}


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
        self.__logger = logging.getLogger(self.__class__.__name__)
        safe_config = redact_sensitive_info(device_config)
        self.__logger.debug('Initialized Executor with device config: %s', safe_config)

    def __enter__(self) -> 'Executor':
        """Enter the runtime context related to this object."""
        self.__logger.debug('Entering context manager')
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit the runtime context and disconnect from the device."""
        self.__logger.debug('Exiting context manager')
        self.disconnect()

    def connect(self) -> None:
        """Establish connection.

        Raises:
            ExecutorConnectionTimeoutError: If connection fails due to timeout.
            ExecutorAuthenticationError: If authentication fails.
            ExecutorSocketError: If a socket error occurs during connection.
        """
        if not self.is_connected():
            self.__logger.info('Attempting to connect to device: %s', self.__device.get('host', self.__device.get('ip')))
            try:
                self.__connection = cast(BaseConnection, ConnectHandler(**self.__device))
                self.__logger.info('Successfully connected to device')
            except NetmikoTimeoutException as err:
                connection_timeout_msg = 'Connection timed out'
                self.__logger.error('Connection timeout: %s', connection_timeout_msg)
                raise ExecutorConnectionTimeoutError(connection_timeout_msg) from err
            except NetmikoAuthenticationException as err:
                authentication_failed_msg = 'Authentication failed'
                self.__logger.error('Authentication failed: %s', authentication_failed_msg)
                raise ExecutorAuthenticationError(authentication_failed_msg) from err
            except OSError as err:
                socket_error_msg = 'Socket error during connection'
                self.__logger.error('Socket error: %s', socket_error_msg)
                raise ExecutorSocketError(socket_error_msg) from err
        else:
            self.__logger.warning('Already connected to the device')

    def disconnect(self) -> None:
        """Send 'exit' and wait until the connection is closed.

        Raises:
            ExecutorDisconnectTimeoutError: If connection doesn't close
                within expected time.
        """
        if self.is_connected():
            self.__logger.info('Attempting to disconnect from device')
            try:
                self._try_disconnect()
                self.__logger.info('Successfully disconnected from device')
            except RetryError as err:
                self.__logger.error('Disconnect timeout after %d retries', 20)
                raise ExecutorDisconnectTimeoutError(retries=20) from err
            self.__connection = None
        else:
            self.__logger.debug('No active connection to disconnect')

    def _send_command(self, command: str, expect_output: str = '.*WG[0-9a-zA-Z()/-]*#$') -> str:
        """Wrapper for Netmiko send_command.

        Args:
            command (str): Command to send.
            expect_output (str): Regular expression for determining output end.

        Returns:
            str: Netmiko send_command output as str.

        Raises:
            ExecuteError: If command execution fails.
        """
        self.__logger.debug('Sending command: %s', command)
        try:
            output = cast(str, self.__connection.send_command(command, expect_string=expect_output))  # type: ignore[union-attr]
            self.__logger.debug('Command executed successfully: %s', command)
            return output
        except NetmikoBaseException as err:
            execute_error_msg = f'Failed to execute command: {command}'
            self.__logger.error('Command execution failed: %s', execute_error_msg)
            raise ExecuteError(execute_error_msg) from err

    def is_connected(self) -> bool:
        """Check if there is connection."""
        status = isinstance(self.__connection, BaseConnection) and self.__connection.is_alive()
        self.__logger.debug('Connection status check: %s', status)
        return status

    @retry(stop=stop_after_attempt(10), wait=wait_fixed(0.5))
    def _try_disconnect(self) -> None:
        """Retry until connection is inactive.

        Raises:
            ExecutorDisconnectTimeoutError: If connection remains active
                after retry period.
        """
        if self.is_connected():
            self.__logger.debug('Sending exit command for disconnection')
            self._send_command('exit', expect_output='')
            if self.is_connected():
                msg = 'Connection still active after exit command'
                self.__logger.warning(msg)
                raise ExecutorDisconnectTimeoutError(msg)

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
            self.__logger.info('Executing command: %s', command)
            return self._send_command(command)
        self.__logger.error(no_connection_msg)
        raise NoConnectionError(no_connection_msg)
