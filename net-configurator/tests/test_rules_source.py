"""Tests for RulesSource class and data readers."""

from contextlib import suppress
from io import StringIO
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from net_configurator.json_file_reader import JSONFileReader
from net_configurator.json_file_reader import NotJSONArrayError
from net_configurator.rule import Rule
from net_configurator.rules_source import ReaderInterface
from net_configurator.rules_source import RulesSource


def test_json_file_reader_with_valid_rules_returns_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSONFileReader returns list for file with JSON array."""
    monkeypatch.setattr(Path, 'open', lambda path, mode: StringIO())  # noqa: ARG005
    monkeypatch.setattr(json, 'load', lambda file: [{'a': 1}])  # noqa: ARG005
    reader = JSONFileReader('file.json')
    with reader:
        result = reader.read_all_rules()
    assert isinstance(result, list)


def test_json_file_reader_without_array_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSONFileReader with no top-level array in JSON should raise."""
    monkeypatch.setattr(Path, 'open', lambda path, mode: StringIO())  # noqa: ARG005
    monkeypatch.setattr(json, 'load', lambda file: {'a': 1})  # noqa: ARG005
    reader = JSONFileReader('file.json')
    with pytest.raises(NotJSONArrayError, match='File content is not an array'), reader:
        reader.read_all_rules()


def test_rules_source_calls_reader() -> None:
    """RulesSource.read_all_rules() calls reader."""
    dummy_reader = Mock(spec=ReaderInterface)
    rules_source = RulesSource(dummy_reader)
    with suppress(TypeError):
        rules_source.read_all_rules()
    dummy_reader.read_all_rules.assert_called_once()


def test_rules_source_with_valid_input() -> None:
    """RulesSource with valid reader data gives valid output."""
    dummy_reader = Mock(spec=ReaderInterface)
    dummy_reader.read_all_rules.return_value = [
        {'sources': [{'ip_low': '10.1.3.173'}], 'destinations': [{'ip_low': '172.31.0.100'}], 'packet_filter': [{'protocol': 'icmp'}]}
    ]
    rules_source = RulesSource(dummy_reader)
    rules = rules_source.read_all_rules()
    assert isinstance(rules, set)
    assert len(rules) == 1
    for rule in rules:
        assert isinstance(rule, Rule)


def test_rules_source_with_empty_array() -> None:
    """RulesSource with empty array."""
    dummy_reader = Mock(spec=ReaderInterface)
    dummy_reader.read_all_rules.return_value = []
    rules_source = RulesSource(dummy_reader)
    rules = rules_source.read_all_rules()
    assert isinstance(rules, set)
    assert len(rules) == 0
