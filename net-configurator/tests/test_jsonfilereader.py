"""Tests for JSONFileReader and JSONFileReaderFactory."""

import io
import json
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from net_configurator.json_file_reader import FileNotOpenedError
from net_configurator.json_file_reader import JSONFileReader
from net_configurator.json_file_reader import JSONFileReaderFactory
from net_configurator.json_file_reader import NotJSONArrayError


def test_context_calls_open_and_close() -> None:
    """Context manager calls open and close."""
    reader = JSONFileReader('file.json')
    with patch.object(reader, 'open') as mock_open, patch.object(reader, 'close') as mock_close:
        with reader:
            mock_open.assert_called_once()
        mock_close.assert_called_once()


def test_open_calls_io_open() -> None:
    """Open calls Path's open."""
    reader = JSONFileReader('file.json')
    with patch.object(io, 'open'):
        reader.open()
        io.open.assert_called_once()  # type: ignore[attr-defined]


def test_close_calls_file_close() -> None:
    """Close calls Path's close."""
    mock_file = MagicMock()
    reader = JSONFileReader('file.json')
    with patch.object(Path, 'open', return_value=mock_file):
        reader.open()
        reader.close()
        mock_file.close.assert_called_once()


def test_read_all_rules_unopened_file_raises() -> None:
    """JSONFileReader.read_all_rules on closed file should raise."""
    reader = JSONFileReader('file.json')
    with pytest.raises(FileNotOpenedError, match='File not opened before reading'):
        reader.read_all_rules()


def test_read_all_rules_with_valid_data_returns_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSONFileReader.read_all_rules returns list for file with JSON array."""
    monkeypatch.setattr(Path, 'open', lambda path, mode: io.StringIO())  # noqa: ARG005
    monkeypatch.setattr(json, 'load', lambda file: [{'a': 1}])  # noqa: ARG005
    reader = JSONFileReader('file.json')
    with reader:
        result = reader.read_all_rules()
    assert isinstance(result, list)
    assert len(result) == 1


def test_read_all_rules_with_empty_array_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSONFileReader.read_all_rules returns empty list for empty JSON array."""
    monkeypatch.setattr(Path, 'open', lambda path, mode: io.StringIO())  # noqa: ARG005
    monkeypatch.setattr(json, 'load', lambda file: [])  # noqa: ARG005
    reader = JSONFileReader('file.json')
    with reader:
        result = reader.read_all_rules()
    assert isinstance(result, list)
    assert not result


def test_read_all_rules_without_array_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSONFileReader.read_all_rules with no top-level array in JSON should raise."""
    monkeypatch.setattr(Path, 'open', lambda path, mode: io.StringIO())  # noqa: ARG005
    monkeypatch.setattr(json, 'load', lambda file: {'a': 1})  # noqa: ARG005
    reader = JSONFileReader('file.json')
    with pytest.raises(NotJSONArrayError, match='File content is not an array'), reader:
        reader.read_all_rules()


def test_read_all_rules_with_invalid_json_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSONFileReader.read_all_rules should raise for invalid JSON."""
    monkeypatch.setattr(Path, 'open', lambda path, mode: io.StringIO())  # noqa: ARG005
    reader = JSONFileReader('file.json')
    with (
        pytest.raises(NotJSONArrayError, match='File content is not valid JSON'),
        patch('json.load', side_effect=json.JSONDecodeError('Invalid', 'doc', 0)),
        reader,
    ):
        reader.read_all_rules()


def test_read_all_filters_unopened_file_raises() -> None:
    """JSONFileReader.read_all_filters on closed file should raise."""
    reader = JSONFileReader('file.json')
    with pytest.raises(FileNotOpenedError, match='File not opened before reading'):
        reader.read_all_filters()


def test_read_all_filters_with_packet_filter_key_valid_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSONFileReader.read_all_filters returns list for valid owners key."""
    monkeypatch.setattr(Path, 'open', lambda path, mode: io.StringIO())  # noqa: ARG005
    monkeypatch.setattr(json, 'load', lambda file: [{'packet_filter': {}}])  # noqa: ARG005
    reader = JSONFileReader('file.json')
    with reader:
        result = reader.read_all_filters()
    assert isinstance(result, list)
    assert len(result) == 1


def test_read_all_filters_without_packet_filter_key_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSONFileReader.read_all_filters returns empty list without packet_filter key."""
    monkeypatch.setattr(Path, 'open', lambda path, mode: io.StringIO())  # noqa: ARG005
    monkeypatch.setattr(json, 'load', lambda file: [{'no_packet_filter': {}}])  # noqa: ARG005
    reader = JSONFileReader('file.json')
    with reader:
        result = reader.read_all_filters()
    assert isinstance(result, list)
    assert not result


def test_read_all_owners_unopened_file_raises() -> None:
    """JSONFileReader.read_all_owners on closed file should raise."""
    reader = JSONFileReader('file.json')
    with pytest.raises(FileNotOpenedError, match='File not opened before reading'):
        reader.read_all_owners()


def test_read_all_owners_with_owners_key_valid_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSONFileReader.read_all_owners returns list[str] for valid owners key."""
    monkeypatch.setattr(Path, 'open', lambda path, mode: io.StringIO())  # noqa: ARG005
    monkeypatch.setattr(json, 'load', lambda file: [{'owners': ['X-x']}])  # noqa: ARG005
    reader = JSONFileReader('file.json')
    with reader:
        result = reader.read_all_owners()
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], str)
    assert result[0] == 'X-x'


def test_read_all_owners_without_owners_key_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """JSONFileReader.read_all_owners returns empty list without owners key."""
    monkeypatch.setattr(Path, 'open', lambda path, mode: io.StringIO())  # noqa: ARG005
    monkeypatch.setattr(json, 'load', lambda file: [{'no_owners': ['X-x']}])  # noqa: ARG005
    reader = JSONFileReader('file.json')
    with reader:
        result = reader.read_all_owners()
    assert isinstance(result, list)
    assert not result


def test_factory_creates_valid_object() -> None:
    """Factory should create JSONFileReader object."""
    factory = JSONFileReaderFactory('file.json')
    reader = factory.create()
    assert isinstance(reader, JSONFileReader)
