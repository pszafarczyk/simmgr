from unittest.mock import MagicMock
from unittest.mock import patch

from netmiko import NetmikoAuthenticationException
from netmiko import NetmikoTimeoutException
import pytest

from net_configurator.executor import AuthenticationError
from net_configurator.executor import ConnectionTimeoutError
from net_configurator.executor import DisconnectTimeoutError
from net_configurator.executor import ExecuteError
from net_configurator.executor import Executor
from net_configurator.executor import NoConnectionError

DEVICE_CONFIG = {
    "device_type": "watchguard_fireware",
    "host": "10.0.0.1",
    "username": "admin",
    "password": "password",
}


@patch("net_configurator.executor.ConnectHandler")
def test_successful_connection_and_execution(mock_connect_handler):
    mock_conn = MagicMock()
    mock_conn.send_command.return_value = "Command output"
    mock_conn.is_alive.return_value = False
    mock_connect_handler.return_value = mock_conn

    executor = Executor(DEVICE_CONFIG)
    executor.connect()
    output = executor.execute("show rule")
    assert output == "Command output"

    executor.disconnect()
    mock_conn.send_command.assert_called_with("exit", expect_string="")
    assert executor._Executor__connection is None


@patch("net_configurator.executor.ConnectHandler", side_effect=NetmikoTimeoutException)
def test_connection_timeout(mock_connect_handler):
    executor = Executor(DEVICE_CONFIG)
    with pytest.raises(ConnectionTimeoutError):
        executor.connect()


@patch("net_configurator.executor.ConnectHandler", side_effect=NetmikoAuthenticationException)
def test_authentication_failure(mock_connect_handler):
    executor = Executor(DEVICE_CONFIG)
    with pytest.raises(AuthenticationError):
        executor.connect()


@patch("net_configurator.executor.ConnectHandler")
def test_disconnect_timeout(mock_connect_handler):
    mock_conn = MagicMock()
    mock_conn.send_command.return_value = ""
    mock_conn.is_alive.side_effect = [True] * 21  # Simulate always alive
    mock_connect_handler.return_value = mock_conn

    executor = Executor(DEVICE_CONFIG)
    executor.connect()

    with pytest.raises(DisconnectTimeoutError):
        executor.disconnect()


def test_execute_without_connection():
    executor = Executor(DEVICE_CONFIG)
    with pytest.raises(NoConnectionError):
        executor.execute("show ip int brief")


@patch("net_configurator.executor.ConnectHandler")
def test_execute_command_failure(mock_connect_handler):
    mock_conn = MagicMock()
    mock_conn.send_command.side_effect = Exception("Something failed")
    mock_conn.is_alive.return_value = False
    mock_connect_handler.return_value = mock_conn

    executor = Executor(DEVICE_CONFIG)
    executor.connect()

    with pytest.raises(ExecuteError):
        executor.execute("bad command")


@patch("net_configurator.executor.ConnectHandler")
def test_context_manager_success(mock_connect_handler):
    mock_conn = MagicMock()
    mock_conn.send_command.return_value = "done"
    mock_conn.is_alive.return_value = False
    mock_connect_handler.return_value = mock_conn

    with Executor(DEVICE_CONFIG) as executor:
        result = executor.execute("test command")
        assert result == "done"
    mock_conn.send_command.assert_any_call("exit", expect_string="")


@patch("net_configurator.executor.ConnectHandler")
def test_del_calls_exit(mock_connect_handler):
    mock_conn = MagicMock()
    mock_connect_handler.return_value = mock_conn
    executor = Executor(DEVICE_CONFIG)
    executor.connect()
    del executor
    mock_conn.send_command.assert_called_with("exit", expect_string="")

