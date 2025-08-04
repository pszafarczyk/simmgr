"""Tests for Executor class."""

# ruff: noqa: SLF001
from collections.abc import Callable
from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import patch

from netmiko import BaseConnection
from netmiko import NetmikoAuthenticationException
from netmiko import NetmikoBaseException
from netmiko import NetmikoTimeoutException
import pytest
from pytest_mock import MockerFixture

from net_configurator.executor import ExecuteError
from net_configurator.executor import Executor
from net_configurator.executor import ExecutorAuthenticationError
from net_configurator.executor import ExecutorConnectionTimeoutError
from net_configurator.executor import ExecutorDisconnectTimeoutError
from net_configurator.executor import NoConnectionError


@pytest.fixture
def device_config() -> dict[str, str]:
    """Provide a sample device configuration dictionary."""
    return {
        'ip': '192.168.1.1',
        'username': 'admin',
        'password': 'password',
        'device_type': 'watchguard_fireware',
    }


@pytest.fixture
def mock_connection() -> Mock:
    """Create a mocked BaseConnection object with default behavior."""
    mock_conn = Mock(spec=BaseConnection)
    mock_conn.is_alive.return_value = True
    mock_conn.send_command.return_value = 'WG#command output'
    return mock_conn


@pytest.fixture
def executor(device_config: dict[str, str], mocker: MockerFixture, mock_connection: Mock) -> Executor:
    """Create an Executor instance with mocked ConnectHandler."""
    mocker.patch('net_configurator.executor.ConnectHandler', return_value=mock_connection)
    return Executor(device_config)


@pytest.fixture
def coordinated_mocks(mocker: MockerFixture) -> Callable[..., tuple[MagicMock, MagicMock]]:  # noqa: C901
    """Factory to create mocks for `_send_command` and `is_connected`."""

    def create_mocks(initially_connected: bool = True, disconnect_after_n_exit_calls: int | None = None) -> tuple[MagicMock, MagicMock]:
        """Create coordinated mocks for _send_command and is_connected.

        Args:
            initially_connected: Initial return value of is_connected.
            disconnect_after_n_exit_calls: Number of 'exit' command calls after which
                                        is_connected returns False.
                                        If None, is_connected never returns False.
        Returns: Tuple of (send_command_mock, is_connected_mock)
        """
        exit_call_count: int = 0

        def send_command(command: str) -> None:
            nonlocal exit_call_count
            if command == 'exit':
                exit_call_count += 1

        def is_connected() -> bool:
            if disconnect_after_n_exit_calls is not None and exit_call_count >= disconnect_after_n_exit_calls:
                return False
            return initially_connected

        send_command_mock = mocker.MagicMock(side_effect=send_command)
        is_connected_mock = mocker.MagicMock(side_effect=is_connected)
        return send_command_mock, is_connected_mock

    return create_mocks


def test_connect_success(executor: Executor) -> None:
    """Verify connect establishes a connection successfully."""
    executor.connect()
    assert executor.is_connected()


def test_connect_timeout(mocker: MockerFixture, device_config: dict[str, str]) -> None:
    """Verify connect raises ExecutorConnectionTimeoutError on timeout."""
    mocker.patch('net_configurator.executor.ConnectHandler', side_effect=NetmikoTimeoutException('Connection timeout'))
    executor = Executor(device_config)
    with pytest.raises(ExecutorConnectionTimeoutError, match='Connection timed out'):
        executor.connect()


def test_connect_authentication_failure(mocker: MockerFixture, device_config: dict[str, str]) -> None:
    """Verify connect raises ExecutorAuthenticationError on authentication failure."""
    mocker.patch('net_configurator.executor.ConnectHandler', side_effect=NetmikoAuthenticationException('Auth failed'))
    executor = Executor(device_config)
    with pytest.raises(ExecutorAuthenticationError, match='Authentication failed'):
        executor.connect()


def test_context_manager_enter(executor: Executor, mock_connection: Mock) -> None:
    """Verify context manager connects and disconnects properly."""
    with executor as ex:
        assert ex is executor
        assert executor.is_connected()
        mock_connection.is_alive.side_effect = [True, False]


def test_context_manager_exit(executor: Executor, coordinated_mocks: Callable[..., tuple[MagicMock, MagicMock]]) -> None:
    """Verify context manager connects and disconnects properly."""
    send_command_mock, is_connected_mock = coordinated_mocks(initially_connected=True, disconnect_after_n_exit_calls=1)
    with patch.object(executor, '_send_command', send_command_mock), patch.object(executor, 'is_connected', is_connected_mock), executor:
        pass
    send_command_mock.assert_called_with('exit')
    assert not executor.is_connected()


def test_disconnect_success(executor: Executor, coordinated_mocks: Callable[..., tuple[MagicMock, MagicMock]]) -> None:
    """Verify disconnect closes the connection successfully."""
    send_command_mock, is_connected_mock = coordinated_mocks(initially_connected=True, disconnect_after_n_exit_calls=1)
    with patch.object(executor, '_send_command', send_command_mock), patch.object(executor, 'is_connected', is_connected_mock):
        executor.disconnect()

    send_command_mock.assert_called_with('exit')
    assert not executor.is_connected()


def test_disconnect_success_with_tries(executor: Executor, coordinated_mocks: Callable[..., tuple[MagicMock, MagicMock]]) -> None:
    """Verify disconnect succeeds after multiple tries."""
    send_command_mock, is_connected_mock = coordinated_mocks(initially_connected=True, disconnect_after_n_exit_calls=4)

    with (
        patch.object(executor, '_send_command', send_command_mock),
        patch.object(executor, 'is_connected', is_connected_mock),
        patch.object(executor.disconnect.retry, 'sleep', Mock()),  # type: ignore[attr-defined]
    ):
        executor.disconnect()

    send_command_mock.assert_called_with('exit')
    assert not executor.is_connected()


def test_disconnect_timeout(executor: Executor, coordinated_mocks: Callable[..., tuple[MagicMock, MagicMock]]) -> None:
    """Verify disconnect raises ExecutorDisconnectTimeoutError on timeout."""
    send_command_mock, is_connected_mock = coordinated_mocks(initially_connected=True, disconnect_after_n_exit_calls=None)
    with (
        patch.object(executor, '_send_command', send_command_mock),
        patch.object(executor, 'is_connected', is_connected_mock),
        patch.object(executor.disconnect.retry, 'sleep', Mock()),  # type: ignore[attr-defined]
        pytest.raises(ExecutorDisconnectTimeoutError, match='Failed to disconnect within timeout period'),
    ):
        executor.disconnect()

    send_command_mock.assert_called_with('exit')
    is_connected_mock.assert_called()


def test_execute_no_connection(executor: Executor) -> None:
    """Verify execute raises NoConnectionError when not connected."""
    executor.__dict__['_Executor__connection'] = None
    with pytest.raises(NoConnectionError, match='No active connection to device'):
        executor.execute('show version')


def test_execute_success(executor: Executor) -> None:
    """Verify execute returns command output when connected."""
    with patch.object(executor, '_send_command', return_value='WG#command output') as mock_send:
        executor.connect()
        result = executor.execute('show version')
        assert result == 'WG#command output'
        mock_send.assert_called_once_with('show version')


def test_execute_command_failure(executor: Executor, mock_connection: Mock) -> None:
    """Verify execute raises ExecuteError on command failure."""
    mock_connection.send_command.side_effect = NetmikoBaseException('Command failed.')
    executor.connect()
    with pytest.raises(ExecuteError, match='Failed to execute command: show version'):
        executor.execute('show version')
