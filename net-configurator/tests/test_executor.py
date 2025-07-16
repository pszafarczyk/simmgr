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

from net_configurator.executor import AuthenticationError
from net_configurator.executor import ConnectionTimeoutError
from net_configurator.executor import DisconnectTimeoutError
from net_configurator.executor import ExecuteError
from net_configurator.executor import Executor
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
    """Verify connect raises ConnectionTimeoutError on timeout."""
    mocker.patch('net_configurator.executor.ConnectHandler', side_effect=NetmikoTimeoutException('Connection timeout'))
    executor = Executor(device_config)
    with pytest.raises(ConnectionTimeoutError, match='Cannot connect to device'):
        executor.connect()


def test_connect_authentication_failure(mocker: MockerFixture, device_config: dict[str, str]) -> None:
    """Verify connect raises AuthenticationError on authentication failure."""
    mocker.patch('net_configurator.executor.ConnectHandler', side_effect=NetmikoAuthenticationException('Auth failed'))
    executor = Executor(device_config)
    with pytest.raises(AuthenticationError, match='Cannot connect to device due to authentication problem'):
        executor.connect()


def test_context_manager(executor: Executor, mock_connection: Mock, mocker: MockerFixture) -> None:
    """Verify context manager connects and disconnects properly."""
    mocker.patch('net_configurator.executor.Executor._wait_for_disconnect')
    with executor as ex:
        assert ex.is_connected()
    mock_connection.send_command.assert_called_once_with('exit', expect_string='')
    assert not ex.is_connected()


def test_disconnect_success(executor: Executor, mock_connection: Mock, mocker: MockerFixture) -> None:
    """Verify disconnect closes the connection successfully."""
    mocker.patch('net_configurator.executor.Executor._wait_for_disconnect')
    executor.connect()
    executor.disconnect()
    mock_connection.send_command.assert_called_once_with('exit', expect_string='')
    assert not executor.is_connected()


def test_disconnect_timeout(executor: Executor, mocker: MockerFixture) -> None:
    """Verify disconnect raises DisconnectTimeoutError on timeout."""
    mock_future = Mock(spec=Future)
    mocker.patch('net_configurator.executor.Executor._wait_for_disconnect', side_effect=RetryError(mock_future))
    executor.connect()
    with pytest.raises(DisconnectTimeoutError, match='SSH connection did not close in time after 20 retries'):
        executor.disconnect()


def test_execute_no_connection(executor: Executor) -> None:
    """Verify execute raises NoConnectionError when not connected."""
    executor.__dict__['_Executor__connection'] = None
    with pytest.raises(NoConnectionError, match='There is no connection'):
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
    with pytest.raises(ExecuteError, match='Command failed.'):
        executor.execute('show version')
