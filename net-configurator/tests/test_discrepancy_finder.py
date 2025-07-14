"""Tests for RuleDiscrepancyFilter class."""

from collections.abc import Callable
from typing import Any

import pytest

from net_configurator.discrepancy_finder import RuleDiscrepancyFinder
from net_configurator.rule import IdentifiedModelInterface
from net_configurator.rule import Rule


@pytest.fixture
def create_ruleset() -> Callable[[str], set[IdentifiedModelInterface]]:
    """Fixture returning ruleset creation function."""
    rules: dict[str, dict[str, Any]] = {
        'a': {'sources': ({'ip_low': '10.1.3.173'},), 'destinations': ({'ip_low': '172.31.0.100'},), 'packet_filter': ({'protocol': 'icmp'},)},
        'b': {'sources': ({'ip_low': '10.1.3.105'},), 'destinations': ({'ip_low': '0.0.0.0/0'},), 'packet_filter': ({'protocol': 'icmp'},)},
        'c': {'sources': ({'ip_low': '10.0.0.0/8'},), 'destinations': ({'ip_low': '0.0.0.0/0'},), 'packet_filter': ({'protocol': 'udp', 'port_low': 53},)},
    }

    def _create_ruleset(symbols: str) -> set[IdentifiedModelInterface]:
        return {Rule(**rules[symbol]) for symbol in symbols}

    return _create_ruleset


@pytest.mark.parametrize('existing_rule_symbols', ['a', 'b', 'c', 'ab', 'bc', 'ac', 'abc'])
def test_discrepancy_empty_desired_give_empty_add(create_ruleset: Callable[[str], set[IdentifiedModelInterface]], existing_rule_symbols: str) -> None:
    """There should be nothing to add when desired rules set is empty."""
    desired_rules: set[Any] = set()
    existing_rules = create_ruleset(existing_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_add()
    assert len(result) == 0


@pytest.mark.parametrize('existing_rule_symbols', ['a', 'b', 'c', 'ab', 'bc', 'ac', 'abc'])
def test_discrepancy_empty_desired_give_existing_to_delete(
    create_ruleset: Callable[[str], set[IdentifiedModelInterface]], existing_rule_symbols: str
) -> None:
    """All existing should be listed for deletion when desired rules set is empty."""
    desired_rules: set[Any] = set()
    existing_rules = create_ruleset(existing_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_delete()
    expected = {rule.identifier for rule in existing_rules}
    assert result == expected


@pytest.mark.parametrize('desired_rule_symbols', ['a', 'b', 'c', 'ab', 'bc', 'ac', 'abc'])
def test_discrepancy_empty_existing_give_desired_to_add(create_ruleset: Callable[[str], set[IdentifiedModelInterface]], desired_rule_symbols: str) -> None:
    """All desired should be listed for addition when existing rules set is empty."""
    desired_rules = create_ruleset(desired_rule_symbols)
    existing_rules: set[Any] = set()
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_add()
    assert result == desired_rules


@pytest.mark.parametrize('desired_rule_symbols', ['a', 'b', 'c', 'ab', 'bc', 'ac', 'abc'])
def test_discrepancy_empty_existing_give_empty_delete(create_ruleset: Callable[[str], set[IdentifiedModelInterface]], desired_rule_symbols: str) -> None:
    """There should be nothing to delete when existing rules set is empty."""
    desired_rules = create_ruleset(desired_rule_symbols)
    existing_rules: set[Any] = set()
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_delete()
    assert len(result) == 0


@pytest.mark.parametrize('both_rule_symbols', ['a', 'b', 'c', 'ab', 'bc', 'ac', 'abc'])
def test_discrepancy_identical_sets_give_empty_add(create_ruleset: Callable[[str], set[IdentifiedModelInterface]], both_rule_symbols: str) -> None:
    """There should be nothing to add when rule sets are identical."""
    desired_rules = create_ruleset(both_rule_symbols)
    existing_rules = create_ruleset(both_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_add()
    assert len(result) == 0


@pytest.mark.parametrize('both_rule_symbols', ['a', 'b', 'c', 'ab', 'bc', 'ac', 'abc'])
def test_discrepancy_identical_sets_give_empty_delete(create_ruleset: Callable[[str], set[IdentifiedModelInterface]], both_rule_symbols: str) -> None:
    """There should be nothing to delete when rule sets are identical."""
    desired_rules = create_ruleset(both_rule_symbols)
    existing_rules = create_ruleset(both_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_delete()
    assert len(result) == 0


@pytest.mark.parametrize(
    'desired_rule_symbols, existing_rule_symbols',
    [('a', 'b'), ('b', 'c'), ('a', 'c'), ('ab', 'c'), ('bc', 'a'), ('ac', 'b'), ('c', 'ab'), ('a', 'bc'), ('b', 'ac')],
)
def test_discrepancy_disjoint_sets_give_desired_to_add(
    create_ruleset: Callable[[str], set[IdentifiedModelInterface]], desired_rule_symbols: str, existing_rule_symbols: str
) -> None:
    """There should be whole desired to add whith disjoint sets."""
    desired_rules = create_ruleset(desired_rule_symbols)
    existing_rules = create_ruleset(existing_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_add()
    assert result == desired_rules


@pytest.mark.parametrize(
    'desired_rule_symbols, existing_rule_symbols',
    [('a', 'b'), ('b', 'c'), ('a', 'c'), ('ab', 'c'), ('bc', 'a'), ('ac', 'b'), ('c', 'ab'), ('a', 'bc'), ('b', 'ac')],
)
def test_discrepancy_disjoint_sets_give_existing_to_delete(
    create_ruleset: Callable[[str], set[IdentifiedModelInterface]], desired_rule_symbols: str, existing_rule_symbols: str
) -> None:
    """There should be whole existing to delete whith disjoint sets."""
    desired_rules = create_ruleset(desired_rule_symbols)
    existing_rules = create_ruleset(existing_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_delete()
    expected = {rule.identifier for rule in existing_rules}
    assert result == expected


@pytest.mark.parametrize(
    'desired_rule_symbols, existing_rule_symbols, expected_result_symbols',
    [
        ('ab', 'a', 'b'),
        ('ab', 'b', 'a'),
        ('bc', 'b', 'c'),
        ('bc', 'c', 'b'),
        ('ac', 'a', 'c'),
        ('ac', 'c', 'a'),
        ('abc', 'a', 'bc'),
        ('abc', 'b', 'ac'),
        ('abc', 'c', 'ab'),
        ('abc', 'ab', 'c'),
        ('abc', 'bc', 'a'),
        ('abc', 'ac', 'b'),
    ],
)
def test_discrepancy_contained_existing_give_difference_to_add(
    create_ruleset: Callable[[str], set[IdentifiedModelInterface]], desired_rule_symbols: str, existing_rule_symbols: str, expected_result_symbols: str
) -> None:
    """Difference should be listed for addition when existing contained in desired."""
    desired_rules = create_ruleset(desired_rule_symbols)
    existing_rules = create_ruleset(existing_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_add()
    expected_result = create_ruleset(expected_result_symbols)
    assert result == expected_result


@pytest.mark.parametrize(
    'desired_rule_symbols, existing_rule_symbols',
    [
        ('ab', 'a'),
        ('ab', 'b'),
        ('bc', 'b'),
        ('bc', 'c'),
        ('ac', 'a'),
        ('ac', 'c'),
        ('abc', 'a'),
        ('abc', 'b'),
        ('abc', 'c'),
        ('abc', 'ab'),
        ('abc', 'bc'),
        ('abc', 'ac'),
    ],
)
def test_discrepancy_contained_existing_give_nothing_to_delete(
    create_ruleset: Callable[[str], set[IdentifiedModelInterface]], desired_rule_symbols: str, existing_rule_symbols: str
) -> None:
    """Nothing should be listed for deletion when existing contained in desired."""
    desired_rules = create_ruleset(desired_rule_symbols)
    existing_rules = create_ruleset(existing_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_delete()
    assert len(result) == 0


@pytest.mark.parametrize(
    'desired_rule_symbols, existing_rule_symbols',
    [
        ('a', 'ab'),
        ('b', 'ab'),
        ('b', 'bc'),
        ('c', 'bc'),
        ('a', 'ac'),
        ('c', 'ac'),
        ('a', 'abc'),
        ('b', 'abc'),
        ('c', 'abc'),
        ('ab', 'abc'),
        ('bc', 'abc'),
        ('ac', 'abc'),
    ],
)
def test_discrepancy_contained_desired_give_nothing_to_add(
    create_ruleset: Callable[[str], set[IdentifiedModelInterface]], desired_rule_symbols: str, existing_rule_symbols: str
) -> None:
    """Nothing should be listed for addition when desired contained in existing."""
    desired_rules = create_ruleset(desired_rule_symbols)
    existing_rules = create_ruleset(existing_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_add()
    assert len(result) == 0


@pytest.mark.parametrize(
    'desired_rule_symbols, existing_rule_symbols, expected_result_symbols',
    [
        ('a', 'ab', 'b'),
        ('b', 'ab', 'a'),
        ('b', 'bc', 'c'),
        ('c', 'bc', 'b'),
        ('a', 'ac', 'c'),
        ('c', 'ac', 'a'),
        ('a', 'abc', 'bc'),
        ('b', 'abc', 'ac'),
        ('c', 'abc', 'ab'),
        ('ab', 'abc', 'c'),
        ('bc', 'abc', 'a'),
        ('ac', 'abc', 'b'),
    ],
)
def test_discrepancy_contained_desired_give_difference_to_delete(
    create_ruleset: Callable[[str], set[IdentifiedModelInterface]], desired_rule_symbols: str, existing_rule_symbols: str, expected_result_symbols: str
) -> None:
    """Difference should be listed for deletion when desired contained in existing."""
    desired_rules = create_ruleset(desired_rule_symbols)
    existing_rules = create_ruleset(existing_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_delete()
    expected_result = {rule.identifier for rule in create_ruleset(expected_result_symbols)}
    assert result == expected_result


@pytest.mark.parametrize(
    'desired_rule_symbols, existing_rule_symbols, expected_result_symbols',
    [('ab', 'bc', 'a'), ('ab', 'ac', 'b'), ('bc', 'ab', 'c'), ('bc', 'ac', 'b'), ('ac', 'ab', 'c'), ('ac', 'bc', 'a')],
)
def test_discrepancy_overlapping_give_desired_minus_existing_to_add(
    create_ruleset: Callable[[str], set[IdentifiedModelInterface]], desired_rule_symbols: str, existing_rule_symbols: str, expected_result_symbols: str
) -> None:
    """Desired-existing should be listed for addition for partially overlapping sets."""
    desired_rules = create_ruleset(desired_rule_symbols)
    existing_rules = create_ruleset(existing_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_add()
    expected_result = create_ruleset(expected_result_symbols)
    assert result == expected_result


@pytest.mark.parametrize(
    'desired_rule_symbols, existing_rule_symbols, expected_result_symbols',
    [('ab', 'bc', 'c'), ('ab', 'ac', 'c'), ('bc', 'ab', 'a'), ('bc', 'ac', 'a'), ('ac', 'ab', 'b'), ('ac', 'bc', 'b')],
)
def test_discrepancy_overlapping_give_existing_minus_desired_to_delete(
    create_ruleset: Callable[[str], set[IdentifiedModelInterface]], desired_rule_symbols: str, existing_rule_symbols: str, expected_result_symbols: str
) -> None:
    """Existing-desired should be listed for deletion for partially overlapping sets."""
    desired_rules = create_ruleset(desired_rule_symbols)
    existing_rules = create_ruleset(existing_rule_symbols)
    finder = RuleDiscrepancyFinder(desired_elements=desired_rules, existing_elements=existing_rules)
    result = finder.get_elements_to_delete()
    expected_result = {rule.identifier for rule in create_ruleset(expected_result_symbols)}
    assert result == expected_result
