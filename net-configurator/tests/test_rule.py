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


@pytest.fixture
def network_peer() -> NetworkPeer:
    """Fixture returning a valid network peer."""
    return NetworkPeer(ip_low='1.1.1.1')


@pytest.fixture(
    params=[
        ([NetworkPeer(ip_low='1.1.1.1')], 1),
        ([NetworkPeer(ip_low='1.1.1.1'), NetworkPeer(ip_low='2.2.2.2')], 2),
        ([NetworkPeer(ip_low='1.1.1.1'), NetworkPeer(ip_low='2.2.2.2'), NetworkPeer(ip_low='1.1.1.1')], 2),
    ]
)
def networkpeers_with_lengths(request: pytest.FixtureRequest) -> tuple[list[NetworkPeer], int]:
    """Fixture returning a list of NetworkPeer with expected lengths."""
    return request.param  # type: ignore[no-any-return]


def test_rule_empty_source_raises(network_peer: NetworkPeer, network_service: NetworkService) -> None:
    """Rule invocation with empty source should raise error."""
    with pytest.raises(ValidationError, match='Tuple should have at least 1 item'):
        Rule(sources=(), destinations=(network_peer,), packet_filter=PacketFilter(services=(network_service,)))


def test_rule_empty_destination_raises(network_peer: NetworkPeer, network_service: NetworkService) -> None:
    """Rule invocation with empty destination should raise error."""
    with pytest.raises(ValidationError, match='Tuple should have at least 1 item'):
        Rule(sources=(network_peer,), destinations=(), packet_filter=PacketFilter(services=(network_service,)))


def test_rule_sources_number_of_elements(networkpeers_with_lengths: tuple[list[NetworkPeer], int], network_service: NetworkService) -> None:
    """Source should be a list of correct number of addresses."""
    networkpeer_list = networkpeers_with_lengths[0]
    expected_length = networkpeers_with_lengths[1]
    rule = Rule(sources=networkpeer_list, destinations=networkpeer_list, packet_filter=PacketFilter(services=(network_service,)))
    assert len(rule.sources) == expected_length


def test_rule_destinations_number_of_elements(networkpeers_with_lengths: tuple[list[NetworkPeer], int], network_service: NetworkService) -> None:
    """Destinations should be a list of correct number of addresses."""
    networkpeer_list = networkpeers_with_lengths[0]
    expected_length = networkpeers_with_lengths[1]
    rule = Rule(sources=networkpeer_list, destinations=networkpeer_list, packet_filter=PacketFilter(services=(network_service,)))
    assert len(rule.destinations) == expected_length


@pytest.mark.parametrize(
    'owners, expected_length',
    [
        (('X-o1',), 1),
        (('X-o1', 'X-o2'), 2),
        (('X-o1', 'X-o2', 'X-o1'), 2),
    ],
)
def test_owners_number_of_elements(owners: tuple[str, ...], expected_length: int) -> None:
    """Owners should have correct number of elements."""
    address = (NetworkPeer(ip_low='172.16.0.1'),)
    services = {'services': (NetworkService(protocol='icmp'),)}
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
    services = {'services': (NetworkService(protocol='icmp'),)}
    expected_length = 0
    rule = Rule(sources=address, destinations=address, packet_filter=services, owners=owners)
    assert len(rule.owners) == expected_length


def test_rule_can_be_set_member(network_service: NetworkService) -> None:
    """It is possible to add Rule to set."""
    rule = Rule(
        sources=(NetworkPeer(ip_low='1.1.1.1'),),
        destinations=(NetworkPeer(ip_low='1.1.1.1'),),
        packet_filter=PacketFilter(services=(network_service,))
    )
    rule_set = set()
    rule_set.add(rule)
    set_size = len(rule_set)
    assert set_size == 1
