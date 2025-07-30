"""Tests for JSONFileReader and JSONFileReaderFactory."""

from io import StringIO
import json
from pathlib import Path

import pytest

from net_configurator.json_file_reader import JSONFileReader
from net_configurator.json_file_reader import NotJSONArrayError


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
