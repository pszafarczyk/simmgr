"""Tests for Namer class."""

import pytest

from net_configurator.namer import Namer


@pytest.mark.parametrize(
    'json_dump, expected_name',
    [
        ('', 'X-da39a3ee5e6b4b0d3255bfef95601890afd80709'),
        ('[]', 'X-97d170e1550eee4afc0af065b78cda302a97674c'),
        ('{}', 'X-bf21a9e8fbc5a3846fb05b4fa0859e0917b2202f'),
        ('{"x": 4}', 'X-0e9495c7713dd296e29911123274e2a4e6ab6470'),
        ('[\n  {\n    "g": "h"\n  }\n]', 'X-b5634d5772f590b6d8dc6e79daf6210dc397ca46'),
    ],
)
def test_generate_name(json_dump: str, expected_name: str) -> None:
    """Correct name should be generated."""
    result = Namer.generate_name(json_dump)
    assert result == expected_name
