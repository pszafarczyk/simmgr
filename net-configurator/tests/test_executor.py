"""Tests for Executor class."""

# ruff: noqa: SLF001
from unittest.mock import Mock
from typing import Any, Dict

from netmiko import BaseConnection
from netmiko import NetmikoAuthenticationException
from netmiko import NetmikoTimeoutException
import pytest
from pytest_mock import MockerFixture  # Import MockerFixture for proper typing
from tenacity import RetryError, Future  # Import Future for RetryError

from net_configurator.executor import AuthenticationError
from net_configurator.executor import ConnectionTimeoutError
from net_configurator.executor import DisconnectTimeoutError
from net_configurator.executor import ExecuteError
from net_configurator.executor import Executor
from net_configurator.executor import NoConnectionError


@pytest.fixture
def device_config() -> Dict[str, str]:
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
    mock_conn.send_command.return_value = 'command output'
    return mock_conn


@pytest.fixture
def executor(device_config: Dict[str, str], mocker: MockerFixture, mock_connection: Mock) -> Executor:
    """Create an Executor instance with mocked ConnectHandler."""
    mocker.patch('net_configurator.executor.ConnectHandler', return_value=mock_connection)
    return Executor(device_config)


def test_initialization(device_config: Dict[str, str]) -> None:
    """Verify Executor initializes with no connection and correct device config."""
    executor = Executor(device_config)
    # Avoid accessing private attributes; test public behavior or use a getter if needed
    # For testing private state, consider refactoring Executor to expose state via properties
    assert executor.__dict__.get('_Executor__connection') is None  # Workaround for private attribute
    assert executor.__dict__.get('_Executor__device') == device_config  # Workaround for private attribute


def test_connect_success(executor: Executor, mock_connection: Mock) -> None:
    """Verify connect establishes a connection successfully."""
    executor.__dict__['_Executor__connection'] = None  # Workaround for private attribute
    executor.connect()
    assert executor.__dict__.get('_Executor__connection') == mock_connection


def test_connect_timeout(mocker: MockerFixture, device_config: Dict[str, str]) -> None:
    """Verify connect raises ConnectionTimeoutError on timeout."""
    mocker.patch('net_configurator.executor.ConnectHandler', side_effect=NetmikoTimeoutException('Connection timeout'))
    executor = Executor(device_config)
    with pytest.raises(ConnectionTimeoutError, match='Cannot connect to device'):
        executor.connect()


def test_connect_authentication_failure(mocker: MockerFixture, device_config: Dict[str, str]) -> None:
    """Verify connect raises AuthenticationError on authentication failure."""
    mocker.patch('net_configurator.executor.ConnectHandler', side_effect=NetmikoAuthenticationException('Auth failed'))
    executor = Executor(device_config)
    with pytest.raises(AuthenticationError, match='Cannot connect to device due to authentication problem'):
        executor.connect()


def test_context_manager(executor: Executor, mock_connection: Mock, mocker: MockerFixture) -> None:
    """Verify context manager connects and disconnects properly."""
    mocker.patch('net_configurator.executor.Executor._wait_for_disconnect')
    with executor as ex:
        assert ex.__dict__.get('_Executor__connection') == mock_connection
    mock_connection.send_command.assert_called_once_with('exit', expect_string='')
    assert executor.__dict__.get('_Executor__connection') is None


def test_disconnect_success(executor: Executor, mock_connection: Mock, mocker: MockerFixture) -> None:
    """Verify disconnect closes the connection successfully."""
    mocker.patch('net_configurator.executor.Executor._wait_for_disconnect')
    executor.connect()
    executor.disconnect()
    mock_connection.send_command.assert_called_once_with('exit', expect_string='')
    assert executor.__dict__.get('_Executor__connection') is None


def test_disconnect_timeout(executor: Executor, mocker: MockerFixture) -> None:
    """Verify disconnect raises DisconnectTimeoutError on timeout."""
    # Create a mock Future object for RetryError
    mock_future = Mock(spec=Future)
    mocker.patch('net_configurator.executor.Executor._wait_for_disconnect', side_effect=RetryError(mock_future))
    executor.connect()
    with pytest.raises(DisconnectTimeoutError, match='SSH connection did not close in time after 20 retries'):
        executor.disconnect()


def test_execute_no_connection(executor: Executor) -> None:
    """Verify execute raises NoConnectionError when not connected."""
    executor.__dict__['_Executor__connection'] = None  # Workaround for private attribute
    with pytest.raises(NoConnectionError, match='There is no connection'):
        executor.execute('show version')


def test_execute_success(executor: Executor, mock_connection: Mock) -> None:
    """Verify execute returns command output when connected."""
    executor.connect()
    result = executor.execute('show version')
    assert result == 'command output'
    mock_connection.send_command.assert_called_once_with('show version')


def test_execute_command_failure(executor: Executor, mock_connection: Mock) -> None:
    """Verify execute raises ExecuteError on command failure."""
    mock_connection.send_command.side_effect = Exception('Command failed.')
    executor.connect()
    with pytest.raises(ExecuteError, match='Command failed.'):
        executor.execute('show version')


def test_destructor_disconnects(executor: Executor, mock_connection: Mock) -> None:
    """Verify destructor disconnects the active connection."""
    executor.__dict__['_Executor__connection'] = mock_connection  # Workaround for private attribute
    executor.__del__()
    mock_connection.send_command.assert_called_once_with('exit', expect_string='')
