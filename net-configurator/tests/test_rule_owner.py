"""Tests for Owner class from `net_configurator.rule` module."""

from pydantic import ValidationError
import pytest

from net_configurator.constants import IDENTIFIER_PREFIX
from net_configurator.rule import Owner


def test_owner_identifier_same_as_name() -> None:
    """Owner's identifier is equal to given name."""
    name = f'{IDENTIFIER_PREFIX}abc'
    owner = Owner(name)
    assert owner.identifier == name


def test_owner_with_no_prefix_raises() -> None:
    """Owner without prefix should raise."""
    with pytest.raises(ValidationError, match='String should match pattern'):
        Owner('abc')


def test_owner_can_be_set_member() -> None:
    """It is possible to add Owner to set."""
    owner = Owner('X-1')
    owner_set = set()
    owner_set.add(owner)
    set_size = len(owner_set)
    assert set_size == 1
