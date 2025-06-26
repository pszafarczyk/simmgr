"""Tests for Rule class from `net_configurator.rule` module."""

import pytest

from net_configurator.rule import NetworkPeer
from net_configurator.rule import NetworkService
from net_configurator.rule import Rule


@pytest.fixture
def rule_filter() -> NetworkService:
    """Fixture returning a valid rule filter."""
    return NetworkService(protocol='tcp', port_low=80)


@pytest.fixture(params=[[NetworkPeer(ip_low='1.1.1.1')], [NetworkPeer(ip_low='1.1.1.1'), NetworkPeer(ip_low='2.2.2.2'), NetworkPeer(ip_low='3.3.3.3')]])
def list_of_ips(request: pytest.FixtureRequest) -> list[NetworkPeer]:
    """Fixture returning a list of IPs."""
    return request.param  # type: ignore[no-any-return]


def test_rule_empty_source_raises(rule_filter: NetworkService) -> None:
    """Rule invocation with empty source should raise error."""
    with pytest.raises(ValueError, match='List should have at least 1 item'):
        Rule(sources=[], destinations=['1.1.1.1'], filter=[rule_filter])


def test_rule_empty_destination_raises(rule_filter: NetworkService) -> None:
    """Rule invocation with empty destination should raise error."""
    with pytest.raises(ValueError, match='List should have at least 1 item'):
        Rule(sources=['1.1.1.1'], destinations=[], filter=[rule_filter])


def test_rule_empty_filter_raises() -> None:
    """Rule invocation with empty filter should raise error."""
    with pytest.raises(ValueError, match='List should have at least 1 item'):
        Rule(sources=['1.1.1.1'], destinations=['1.1.1.1'], filter=[])


def test_rule_source_number_and_type_of_elements(list_of_ips: list[NetworkPeer], rule_filter: NetworkService) -> None:
    """Source should be a list of correct number of IPv4Address."""
    rule = Rule(sources=list_of_ips, destinations=list_of_ips, filter=[rule_filter])
    expected_number_of_ips = len(list_of_ips)
    assert len(rule.sources) == expected_number_of_ips
    for source in rule.sources:
        assert isinstance(source, NetworkPeer)


def test_rule_destination_number_and_type_of_elements(list_of_ips: list[NetworkPeer], rule_filter: NetworkService) -> None:
    """Destinations should be a list of correct number of IPv4Address."""
    rule = Rule(sources=list_of_ips, destinations=list_of_ips, filter=[rule_filter])
    expected_number_of_ips = len(list_of_ips)
    assert len(rule.destinations) == expected_number_of_ips
    for destination in rule.destinations:
        assert isinstance(destination, NetworkPeer)


@pytest.mark.parametrize('number_of_filters', [1, 3])
def test_filter_number_of_elements(rule_filter: NetworkService, number_of_filters: int) -> None:
    """Filter should have correct number of elements."""
    network_peer = NetworkPeer(ip_low='1.1.1.1')
    rule = Rule(sources=[network_peer], destinations=[network_peer], filter=[rule_filter] * number_of_filters)
    assert len(rule.filter.root) == number_of_filters
