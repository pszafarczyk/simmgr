"""Tests for RulesSource class and data readers."""

from contextlib import suppress
from io import StringIO
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from net_configurator.rule import Rule
from net_configurator.rule import RulePeer
from net_configurator.rules_source import JSONFileReader
from net_configurator.rules_source import ReaderInterface
from net_configurator.rules_source import RulesSource


def test_json_file_reader_with_valid_input(monkeypatch: pytest.MonkeyPatch) -> None:
    """Valid JSON source file."""
    monkeypatch.setattr(Path, 'open', lambda path: StringIO())  # noqa: ARG005
    monkeypatch.setattr(json, 'load', lambda file: [{'a': 1}])  # noqa: ARG005
    reader = JSONFileReader('file.json')
    result = reader.read_all()
    assert isinstance(result, list)


# def test_json_file_reader_without_array() -> None:
#     """JSONFileReader with no top-level array in JSON should raise."""
#     assert False


# def test_json_file_reader_with_invalid_json_should_raise() -> None:
#     """JSONFileReader with invalid JSON should raise."""
#     assert False


def test_rules_source_calls_reader() -> None:
    """RulesSource.read_all() calls reader."""
    dummy_reader = Mock(spec=ReaderInterface)
    rules_source = RulesSource(dummy_reader)
    with suppress(TypeError):
        rules_source.read_all()
    dummy_reader.read_all.assert_called_once()


def test_rules_source_with_valid_input() -> None:
    """RulesSource with valid reader data gives valid output."""
    dummy_reader = Mock(spec=ReaderInterface)
    dummy_reader.read_all.return_value = [
        {'sources': [RulePeer(ip_low='1.1.1.1')], 'destinations': [RulePeer(ip_low='2.2.2.2')], 'filters': [{'protocol': 'icmp'}]}
    ]
    rules_source = RulesSource(dummy_reader)
    rules = rules_source.read_all()
    assert isinstance(rules, list)
    assert len(rules) == 1
    assert isinstance(rules[0], Rule)


def test_rules_source_with_empty_array() -> None:
    """RulesSource with empty array."""
    dummy_reader = Mock(spec=ReaderInterface)
    dummy_reader.read_all.return_value = []
    rules_source = RulesSource(dummy_reader)
    rules = rules_source.read_all()
    assert isinstance(rules, list)
    assert len(rules) == 0
