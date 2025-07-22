"""Tests for WatchguardParser class from `net_configurator.watchguard_parser` module."""

import json
from pathlib import Path

import pytest

from net_configurator.watchguard_parser import WatchguardParser


@pytest.fixture
def parser():
    """Provide a WatchguardParser instance."""
    return WatchguardParser()


@pytest.fixture
def test_data_path():
    """Provide the path to test_data directory."""
    return Path(__file__).parent / 'test_data'


def read_test_file(test_data_path, subdir, filename):
    """Helper to read test file content from a subdirectory."""
    with open(test_data_path / subdir / filename) as f:
        return f.read()


def get_snapshot_filename(request, filename):
    """Generate a snapshot filename based on the test name and input filename."""
    return f'{Path(filename).stem}.json'


def to_serializable(obj):
    """Recursively convert objects to JSON-serializable format."""
    if hasattr(obj, 'to_dict'):
        return obj.to_dict()
    if isinstance(obj, list):
        return [to_serializable(item) for item in obj]
    if isinstance(obj, dict):
        return {key: to_serializable(value) for key, value in obj.items()}
    return obj


def get_test_files(test_data_path, subdir):
    """Return a list of .txt filenames in the specified subdirectory."""
    return [file.name for file in (test_data_path / subdir).glob('*.txt')]


@pytest.mark.parametrize(
    'subdir,filename',
    [('extract_rule_name_data', fname) for fname in get_test_files(Path(__file__).parent / 'test_data', 'extract_rule_name_data')],
)
def test_extract_rule_names(parser, test_data_path, subdir, filename, snapshot, request):
    """Test extracting rule names and assert against snapshot."""
    data = read_test_file(test_data_path, subdir, filename)
    result = parser.extract_rule_names(data)
    serializable_result = to_serializable(result)
    snapshot_filename = get_snapshot_filename(request, filename)
    snapshot.assert_match(json.dumps(serializable_result, indent=2), snapshot_filename)


@pytest.mark.parametrize(
    'subdir,filename',
    [('parse_rule_data', fname) for fname in get_test_files(Path(__file__).parent / 'test_data', 'parse_rule_data')],
)
def test_parse_rule(parser, test_data_path, subdir, filename, snapshot, request):
    """Test parsing rules and assert against snapshot."""
    data = read_test_file(test_data_path, subdir, filename)
    result = parser.parse_rule(data)
    print(f'Test: {request.node.name}, Subdir: {subdir}, Filename: {filename}, Result type: {type(result)}, Result: {result}')
    serializable_result = to_serializable(result)
    snapshot_filename = get_snapshot_filename(request, filename)
    snapshot.assert_match(json.dumps(serializable_result, indent=2), snapshot_filename)


@pytest.mark.parametrize(
    'subdir,filename',
    [('filter_data', fname) for fname in get_test_files(Path(__file__).parent / 'test_data', 'filter_data')],
)
def test_parse_filter(parser, test_data_path, subdir, filename, snapshot, request):
    """Test parsing filters and assert against snapshot."""
    data = read_test_file(test_data_path, subdir, filename)
    result = parser.parse_filter(data)
    print(f'Test: {request.node.name}, Subdir: {subdir}, Filename: {filename}, Result type: {type(result)}, Result: {result}')
    serializable_result = to_serializable(result)
    snapshot_filename = get_snapshot_filename(request, filename)
    snapshot.assert_match(json.dumps(serializable_result, indent=2), snapshot_filename)
