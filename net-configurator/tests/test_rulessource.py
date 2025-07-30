"""Tests for RulesSource class."""

from contextlib import suppress
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule
from net_configurator.rules_source import DeserializationError
from net_configurator.rules_source import ReaderInterface
from net_configurator.rules_source import RulesSource


@pytest.fixture
def dummy_reader() -> ReaderInterface:
    """Fixture returning mock reader."""
    return Mock(spec=ReaderInterface)


def test_context_calls_open_and_close(dummy_reader: ReaderInterface) -> None:
    """RuleSource's context calls open and close."""
    rules_source = RulesSource(dummy_reader)
    with patch.object(rules_source, 'open') as mock_open, patch.object(rules_source, 'close') as mock_close:
        with rules_source:
            mock_open.assert_called_once()
        mock_close.assert_called_once()


def test_open_calls_readers_open(dummy_reader: ReaderInterface) -> None:
    """RuleSource's open opens reader."""
    rules_source = RulesSource(dummy_reader)
    rules_source.open()
    dummy_reader.open.assert_called_once()  # type: ignore[attr-defined]


def test_close_calls_readers_close(dummy_reader: ReaderInterface) -> None:
    """RuleSource's close closes reader."""
    rules_source = RulesSource(dummy_reader)
    rules_source.close()
    dummy_reader.close.assert_called_once()  # type: ignore[attr-defined]


def test_read_all_rules_calls_reader(dummy_reader: ReaderInterface) -> None:
    """RulesSource.read_all_rules calls reader's read_all_rules."""
    rules_source = RulesSource(dummy_reader)
    with suppress(TypeError):
        rules_source.read_all_rules()
    dummy_reader.read_all_rules.assert_called_once()  # type: ignore[attr-defined]


def test_read_all_rules_with_valid_input_gives_set_of_rules(dummy_reader: ReaderInterface) -> None:
    """RulesSource.read_all_rules with valid reader data gives valid output."""
    dummy_reader.read_all_rules.return_value = [  # type: ignore[attr-defined]
        {'sources': [{'ip_low': '10.1.3.173'}], 'destinations': [{'ip_low': '172.31.0.100'}], 'packet_filter': {'services': [{'protocol': 'icmp'}]}}
    ]
    rules_source = RulesSource(dummy_reader)
    rules = rules_source.read_all_rules()
    assert isinstance(rules, set)
    assert len(rules) == 1
    rule = rules.pop()
    assert isinstance(rule, Rule)


def test_read_all_rules_with_empty_array_gives_empty_set(dummy_reader: ReaderInterface) -> None:
    """RulesSource.read_all_rules with empty array."""
    dummy_reader.read_all_rules.return_value = []  # type: ignore[attr-defined]
    rules_source = RulesSource(dummy_reader)
    rules = rules_source.read_all_rules()
    assert isinstance(rules, set)
    assert len(rules) == 0


def test_read_all_rules_incorrect_identifier_raises(dummy_reader: ReaderInterface) -> None:
    """RulesSource.read_all_rules with incorrect identifier raises."""
    dummy_reader.read_all_rules.return_value = [  # type: ignore[attr-defined]
        {
            'identifier': 'Y-85ccc1a107a3a30134972666b36b8cc03d84f7e2',
            'sources': [{'ip_low': '10.1.3.173'}],
            'destinations': [{'ip_low': '172.31.0.200'}],
            'packet_filter': {'services': [{'protocol': 'icmp'}]},
        }
    ]
    rules_source = RulesSource(dummy_reader)
    with pytest.raises(DeserializationError, match='Found incorrect rule identifier Y-85ccc1a107a3a30134972666b36b8cc03d84f7e2'):
        rules_source.read_all_rules()


def test_read_all_rules_correct_identifier_valid_output(dummy_reader: ReaderInterface) -> None:
    """RulesSource.read_all_rules with correct identifier creates object."""
    dummy_reader.read_all_rules.return_value = [  # type: ignore[attr-defined]
        {
            'identifier': 'X-85ccc1a107a3a30134972666b36b8cc03d84f7e2',
            'sources': [{'ip_low': '10.1.3.173'}],
            'destinations': [{'ip_low': '172.31.0.200'}],
            'packet_filter': {'services': [{'protocol': 'icmp'}]},
        }
    ]
    rules_source = RulesSource(dummy_reader)
    rules = rules_source.read_all_rules()
    assert isinstance(rules, set)
    rule = rules.pop()
    assert isinstance(rule, Rule)
    assert rule.identifier == 'X-85ccc1a107a3a30134972666b36b8cc03d84f7e2'


def test_read_all_filters_calls_reader(dummy_reader: ReaderInterface) -> None:
    """RulesSource.read_all_filters calls reader's read_all_filters."""
    rules_source = RulesSource(dummy_reader)
    with suppress(TypeError):
        rules_source.read_all_filters()
    dummy_reader.read_all_filters.assert_called_once()  # type: ignore[attr-defined]


def test_read_all_filters_with_valid_input_gives_set_of_filters(dummy_reader: ReaderInterface) -> None:
    """RulesSource.read_all_filters with valid reader data gives valid output."""
    dummy_reader.read_all_filters.return_value = [{'services': [{'protocol': 'icmp'}]}]  # type: ignore[attr-defined]
    rules_source = RulesSource(dummy_reader)
    packet_filters = rules_source.read_all_filters()
    assert isinstance(packet_filters, set)
    assert len(packet_filters) == 1
    packet_filter = packet_filters.pop()
    assert isinstance(packet_filter, PacketFilter)


def test_read_all_filters_incorrect_identifier_raises(dummy_reader: ReaderInterface) -> None:
    """RulesSource.read_all_filters with incorrect identifier raises."""
    dummy_reader.read_all_filters.return_value = [  # type: ignore[attr-defined]
        {'identifier': 'Y-4183ca61d4fe56bb913ec7cc344eff1123648f52', 'services': [{'protocol': 'icmp'}]}
    ]
    rules_source = RulesSource(dummy_reader)
    with pytest.raises(DeserializationError, match='Found incorrect packet filter identifier Y-4183ca61d4fe56bb913ec7cc344eff1123648f52'):
        rules_source.read_all_filters()


def test_read_all_filters_correct_identifier_valid_output(dummy_reader: ReaderInterface) -> None:
    """RulesSource.read_all_filters with correct identifier creates object."""
    dummy_reader.read_all_filters.return_value = [  # type: ignore[attr-defined]
        {'identifier': 'X-4183ca61d4fe56bb913ec7cc344eff1123648f52', 'services': [{'protocol': 'icmp'}]}
    ]
    rules_source = RulesSource(dummy_reader)
    packet_filters = rules_source.read_all_filters()
    assert isinstance(packet_filters, set)
    packet_filter = packet_filters.pop()
    assert isinstance(packet_filter, PacketFilter)
    assert packet_filter.identifier == 'X-4183ca61d4fe56bb913ec7cc344eff1123648f52'


def test_read_all_owners_calls_reader(dummy_reader: ReaderInterface) -> None:
    """RulesSource.read_all_owners calls reader's read_all_owners."""
    rules_source = RulesSource(dummy_reader)
    with suppress(TypeError):
        rules_source.read_all_owners()
    dummy_reader.read_all_owners.assert_called_once()  # type: ignore[attr-defined]


def test_read_all_owners_with_valid_input_gives_set_of_owners(dummy_reader: ReaderInterface) -> None:
    """RulesSource.read_all_owners with valid reader data gives valid output."""
    dummy_reader.read_all_owners.return_value = ['X-1']  # type: ignore[attr-defined]
    rules_source = RulesSource(dummy_reader)
    owners = rules_source.read_all_owners()
    assert isinstance(owners, set)
    assert len(owners) == 1
    owner = owners.pop()
    assert isinstance(owner, Owner)
