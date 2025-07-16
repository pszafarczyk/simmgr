"""Tests for Executor class."""

# ruff: noqa: SLF001
from unittest.mock import Mock
from unittest.mock import patch

from netmiko import BaseConnection
from netmiko import NetmikoAuthenticationException
from netmiko import NetmikoBaseException
from netmiko import NetmikoTimeoutException
import pytest
from pytest_mock import MockerFixture
from tenacity import Future
from tenacity import RetryError

from net_configurator.executor import Executor
from net_configurator.executor import ExecutorAuthenticationError
from net_configurator.executor import ExecutorConnectionTimeoutError
from net_configurator.executor import ExecutorDisconnectTimeoutError
from net_configurator.executor import ExecuteError
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


def test_context_manager(executor: Executor, mock_connection: Mock, mocker: MockerFixture) -> None:
    """Verify context manager connects and disconnects properly."""
    with executor as ex:
        assert ex is executor
        assert executor.is_connected()
        mock_connection.is_alive.side_effect = [True, False]
    mock_connection.send_command.assert_called_once_with('exit', expect_string='')
    assert not executor.is_connected()


def test_disconnect_success(executor: Executor, mock_connection: Mock, mocker: MockerFixture) -> None:
    """Verify disconnect closes the connection successfully."""
    executor.connect()
    mock_connection.is_alive.side_effect = [True, False]
    executor.disconnect()
    mock_connection.send_command.assert_called_once_with('exit', expect_string='')
    assert not executor.is_connected()


def test_disconnect_success_with_tries(executor: Executor, mock_connection: Mock, mocker: MockerFixture) -> None:
    """Verify disconnect succeeds after multiple tries."""
    executor.connect()
    mock_connection.is_alive.side_effect = [True, True, True, False]
    executor.disconnect()
    assert mock_connection.send_command.call_count == 3
    mock_connection.send_command.assert_called_with('exit', expect_string='')
    assert not executor.is_connected()


def test_disconnect_timeout(executor: Executor, mocker: MockerFixture) -> None:
    """Verify disconnect raises ExecutorDisconnectTimeoutError on timeout."""
    mock_future = Mock(spec=Future)
    mocker.patch('net_configurator.executor.Executor._try_disconnect', side_effect=RetryError(mock_future))
    executor.connect()
    with pytest.raises(ExecutorDisconnectTimeoutError, match='Failed to disconnect within timeout period'):
        executor.disconnect()


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
