"""Tests for RulesTarget class and data writers."""

from unittest.mock import Mock

import pytest

from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule
from net_configurator.rules_target import ReaderWriterInterface
from net_configurator.rules_target import RulesTarget


@pytest.fixture
def dummy_writer() -> ReaderWriterInterface:
    """Fixture returning mock reader."""
    return Mock(spec=ReaderWriterInterface)


@pytest.fixture
def dummy_rule() -> Rule:
    """Fixture returning mock Rule."""
    return Mock(spec=Rule)


@pytest.fixture
def dummy_filter() -> Rule:
    """Fixture returning mock PacketFilter."""
    return Mock(spec=PacketFilter)


@pytest.fixture
def dummy_owner() -> Rule:
    """Fixture returning mock Owner."""
    return Mock(spec=Owner)


@pytest.fixture
def dummy_identifier() -> str:
    """Fixture returning identifier."""
    return 'identifier'


def test_add_rule_calls_writer(dummy_writer: ReaderWriterInterface, dummy_rule: Rule) -> None:
    """RulesTarget.add_rule calls handler's add_rule."""
    rules_target = RulesTarget(dummy_writer)
    rules_target.add_rule(dummy_rule)
    dummy_writer.add_rule.assert_called_once()  # type: ignore[attr-defined]


def test_delete_rule_calls_writer(dummy_writer: ReaderWriterInterface, dummy_identifier: str) -> None:
    """RulesTarget.delete_rule calls handler's delete_rule."""
    rules_target = RulesTarget(dummy_writer)
    rules_target.delete_rule(dummy_identifier)
    dummy_writer.delete_rule.assert_called_once()  # type: ignore[attr-defined]


def test_add_filter_calls_writer(dummy_writer: ReaderWriterInterface, dummy_filter: PacketFilter) -> None:
    """RulesTarget.add_filter calls handler's add_filter."""
    rules_target = RulesTarget(dummy_writer)
    rules_target.add_filter(dummy_filter)
    dummy_writer.add_filter.assert_called_once()  # type: ignore[attr-defined]


def test_delete_filter_calls_writer(dummy_writer: ReaderWriterInterface, dummy_identifier: str) -> None:
    """RulesTarget.delete_filter calls handler's delete_filter."""
    rules_target = RulesTarget(dummy_writer)
    rules_target.delete_filter(dummy_identifier)
    dummy_writer.delete_filter.assert_called_once()  # type: ignore[attr-defined]


def test_add_owner_calls_writer(dummy_writer: ReaderWriterInterface, dummy_owner: Owner) -> None:
    """RulesTarget.add_owner calls handler's add_owner."""
    rules_target = RulesTarget(dummy_writer)
    rules_target.add_owner(dummy_owner)
    dummy_writer.add_owner.assert_called_once()  # type: ignore[attr-defined]


def test_delete_owner_calls_writer(dummy_writer: ReaderWriterInterface, dummy_identifier: str) -> None:
    """RulesTarget.delete_owner calls handler's delete_owner."""
    rules_target = RulesTarget(dummy_writer)
    rules_target.delete_owner(dummy_identifier)
    dummy_writer.delete_owner.assert_called_once()  # type: ignore[attr-defined]


def test_apply_changes_calls_writer(dummy_writer: ReaderWriterInterface) -> None:
    """RulesTarget.apply_changes calls handler's apply_changes."""
    rules_target = RulesTarget(dummy_writer)
    rules_target.apply_changes()
    dummy_writer.apply_changes.assert_called_once()  # type: ignore[attr-defined]
