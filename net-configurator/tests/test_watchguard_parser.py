"""Tests for WatchguardParser class from `net_configurator.watchguard_parser` module."""

import json
from pathlib import Path
from typing import Any

import pytest

from net_configurator.watchguard_parser import WatchguardParser


@pytest.fixture
def parser() -> WatchguardParser:
    """Provide a WatchguardParser instance."""
    return WatchguardParser()


@pytest.fixture
def test_data_path() -> Path:
    """Provide the path to test_data directory."""
    return Path(__file__).parent / 'test_data'


def read_test_file(test_data_path: Path, subdir: str, filename: str) -> Any:
    """Helper to read test file content from a subdirectory."""
    with open(test_data_path / subdir / filename) as f:
        return f.read()


def get_snapshot_filename(filename: str) -> str:
    """Generate a snapshot filename based on the test name and input filename."""
    return f'{Path(filename).stem}.json'


def to_serializable(obj: Any) -> Any:
    """Recursively convert objects to JSON-serializable format."""
    if hasattr(obj, 'to_dict'):
        return obj.to_dict()
    if isinstance(obj, list):
        return [to_serializable(item) for item in obj]
    if isinstance(obj, dict):
        return {key: to_serializable(value) for key, value in obj.items()}
    return obj


def get_test_files(test_data_path: Path, subdir: str) -> list[str]:
    """Return a list of .txt filenames in the specified subdirectory."""
    return [file.name for file in (test_data_path / subdir).glob('*.txt')]


@pytest.mark.parametrize(
    'subdir,filename',
    [('extract_rule_name_data', fname) for fname in get_test_files(Path(__file__).parent / 'test_data', 'extract_rule_name_data')],
)
def test_extract_rule_names(parser: WatchguardParser, test_data_path: Path, subdir: str, filename: str, snapshot: Any) -> None:
    """Test extracting rule names and assert against snapshot."""
    data = read_test_file(test_data_path, subdir, filename)
    result = parser.extract_rule_names(data)
    serializable_result = to_serializable(result)
    snapshot_filename = get_snapshot_filename(filename)
    snapshot.assert_match(json.dumps(serializable_result, indent=2), snapshot_filename)


@pytest.mark.parametrize(
    'subdir,filename',
    [('parse_rule_data', fname) for fname in get_test_files(Path(__file__).parent / 'test_data', 'parse_rule_data')],
)
def test_parse_rule(  # noqa: PLR0913
    parser: WatchguardParser, test_data_path: Path, subdir: str, filename: str, snapshot: Any, request: Any
) -> None:
    """Test parsing rules and assert against snapshot."""
    data = read_test_file(test_data_path, subdir, filename)
    result = parser.parse_rule(data)
    print(f'Test: {request.node.name}, Subdir: {subdir}, Filename: {filename}, Result type: {type(result)}, Result: {result}')
    serializable_result = to_serializable(result)
    snapshot_filename = get_snapshot_filename(filename)
    snapshot.assert_match(json.dumps(serializable_result, indent=2), snapshot_filename)


@pytest.mark.parametrize(
    'subdir,filename',
    [('filter_data', fname) for fname in get_test_files(Path(__file__).parent / 'test_data', 'filter_data')],
)
def test_parse_filter(  # noqa: PLR0913
    parser: WatchguardParser, test_data_path: Path, subdir: str, filename: str, snapshot: Any, request: Any
) -> None:
    """Test parsing filters and assert against snapshot."""
    data = read_test_file(test_data_path, subdir, filename)
    result = parser.parse_filter(data)
    print(f'Test: {request.node.name}, Subdir: {subdir}, Filename: {filename}, Result type: {type(result)}, Result: {result}')
    serializable_result = to_serializable(result)
    snapshot_filename = get_snapshot_filename(filename)
    snapshot.assert_match(json.dumps(serializable_result, indent=2), snapshot_filename)
