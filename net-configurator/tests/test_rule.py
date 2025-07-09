"""Tests for Rule class from `net_configurator.rule` module."""

from pydantic import ValidationError
import pytest

from net_configurator.rule import NetworkPeer
from net_configurator.rule import NetworkService
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule


@pytest.fixture
def network_service() -> NetworkService:
    """Fixture returning a valid network service."""
    return NetworkService(protocol='tcp', port_low=80)


@pytest.fixture(
    params=[
        ([NetworkPeer(ip_low='1.1.1.1')], 1),
        ([NetworkPeer(ip_low='1.1.1.1'), NetworkPeer(ip_low='2.2.2.2')], 2),
        ([NetworkPeer(ip_low='1.1.1.1'), NetworkPeer(ip_low='2.2.2.2'), NetworkPeer(ip_low='1.1.1.1')], 2),
    ]
)
def list_of_ips_with_lengths(request: pytest.FixtureRequest) -> tuple[list[NetworkPeer], int]:
    """Fixture returning a list of IPs."""
    return request.param  # type: ignore[no-any-return]


def test_rule_empty_source_raises(network_service: NetworkService) -> None:
    """Rule invocation with empty source should raise error."""
    with pytest.raises(ValidationError, match='Tuple should have at least 1 item'):
        Rule(sources=(), destinations=('1.1.1.1',), packet_filter=(network_service,))


def test_rule_empty_destination_raises(network_service: NetworkService) -> None:
    """Rule invocation with empty destination should raise error."""
    with pytest.raises(ValidationError, match='Tuple should have at least 1 item'):
        Rule(sources=('1.1.1.1',), destinations=(), packet_filter=(network_service,))


def test_rule_empty_filter_raises() -> None:
    """Rule invocation with empty filter should raise error."""
    with pytest.raises(ValidationError, match='Tuple should have at least 1 item'):
        Rule(sources=('1.1.1.1',), destinations=('1.1.1.1',), packet_filter=())


def test_rule_sources_number_of_elements(list_of_ips_with_lengths: tuple[list[NetworkPeer], int], network_service: NetworkService) -> None:
    """Source should be a list of correct number of addresses."""
    list_of_ips = list_of_ips_with_lengths[0]
    expected_length = list_of_ips_with_lengths[1]
    rule = Rule(sources=list_of_ips, destinations=list_of_ips, packet_filter=[network_service])
    assert len(rule.sources) == expected_length


def test_rule_destinations_number_of_elements(list_of_ips_with_lengths: tuple[list[NetworkPeer], int], network_service: NetworkService) -> None:
    """Destinations should be a list of correct number of addresses."""
    list_of_ips = list_of_ips_with_lengths[0]
    expected_length = list_of_ips_with_lengths[1]
    rule = Rule(sources=list_of_ips, destinations=list_of_ips, packet_filter=[network_service])
    assert len(rule.destinations) == expected_length


@pytest.mark.parametrize(
    'network_services, expected_length',
    [
        ((NetworkService(protocol='icmp'),), 1),
        ((NetworkService(protocol='icmp'), NetworkService(protocol='udp', port_low=3478)), 2),
        ((NetworkService(protocol='icmp'), NetworkService(protocol='udp', port_low=3478), NetworkService(protocol='icmp')), 2),
    ],
)
def test_filter_number_of_elements(network_services: tuple[NetworkService, ...], expected_length: int) -> None:
    """Filter should have correct number of elements."""
    packet_filter = PacketFilter(network_services)
    assert len(packet_filter.root) == expected_length


@pytest.mark.parametrize(
    'owners, expected_length',
    [
        (('o1',), 1),
        (('o1', 'o2'), 2),
        (('o1', 'o2', 'o1'), 2),
    ],
)
def test_owners_number_of_elements(owners: tuple[str, ...], expected_length: int) -> None:
    """Owners should have correct number of elements."""
    address = (NetworkPeer(ip_low='172.16.0.1'),)
    services = (NetworkService(protocol='icmp'),)
    rule = Rule(sources=address, destinations=address, packet_filter=services, owners=owners)
    assert len(rule.owners) == expected_length


@pytest.mark.parametrize(
    'owners',
    [
        None,
        (),
    ],
)
def test_no_owners_number_of_elements(owners: tuple[str, ...] | None) -> None:
    """Empty owners should have correct number of elements."""
    address = (NetworkPeer(ip_low='172.16.0.1'),)
    services = (NetworkService(protocol='icmp'),)
    expected_length = 0
    rule = Rule(sources=address, destinations=address, packet_filter=services, owners=owners)
    assert len(rule.owners) == expected_length
