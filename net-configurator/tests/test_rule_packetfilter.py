"""Tests for PacketFilter class from `net_configurator.rule` module."""

from pydantic import ValidationError
import pytest

from net_configurator.rule import NetworkService
from net_configurator.rule import PacketFilter


@pytest.mark.parametrize(
    'services, expected_identifier',
    [
        ((NetworkService(protocol='tcp', port_low=443),), 'X-050935040a509710b340d494fdfa7731ac5003bd'),
        (
            (NetworkService(protocol='udp', port_low=514), NetworkService(protocol='udp', port_low=3000, port_high=3009)),
            'X-0a4d107b26cdb5a36d8fca3dbb8acdb697385281',
        ),
    ],
)
def test_packetfilter_has_correct_identifier(services: tuple[NetworkService, ...], expected_identifier: str) -> None:
    """Identifier attribute is as expected."""
    packet_filter = PacketFilter(services=services)
    assert packet_filter.identifier == expected_identifier


def test_packetfilter_identifier_independent_of_order() -> None:
    """Filter's identifier should be independent of services order."""
    service_icmp = NetworkService(protocol='icmp')
    service_tcp = NetworkService(protocol='tcp', port_low=80)
    filter_icmp_tcp = PacketFilter(services=(service_icmp, service_tcp))
    filter_tcp_icmp = PacketFilter(services=(service_tcp, service_icmp))
    assert filter_icmp_tcp.identifier == filter_tcp_icmp.identifier


def test_packetfilter_with_no_services_raises() -> None:
    """PacketFilter shoud raise with no services."""
    with pytest.raises(ValidationError, match='Field required'):
        PacketFilter()  # type: ignore[call-arg]


def test_packetfilter_with_none_raises() -> None:
    """PacketFilter shoud raise with no services."""
    with pytest.raises(ValidationError, match='Input should be a valid tuple'):
        PacketFilter(services=None)


def test_packetfilter_with_empty_services_raises() -> None:
    """PacketFilter shoud raise with no services."""
    with pytest.raises(ValidationError, match='Tuple should have at least 1 item after validation'):
        PacketFilter(services=())


@pytest.mark.parametrize(
    'services, expected_length',
    [
        ((NetworkService(protocol='tcp', port_low=443),), 1),
        ((NetworkService(protocol='tcp', port_low=80), NetworkService(protocol='tcp', port_low=80)), 1),
        ((NetworkService(protocol='udp', port_low=514), NetworkService(protocol='udp', port_low=3000, port_high=3009)), 2),
    ],
)
def test_packetfilter_has_correct_number_of_services(services: tuple[NetworkService, ...], expected_length: int) -> None:
    """PacketFilter should have correct number of services."""
    packet_filter = PacketFilter(services=services)
    assert len(packet_filter.services) == expected_length


def test_packetfilter_can_be_set_member() -> None:
    """It is possible to add PacketFilter to set."""
    packet_filter = PacketFilter(services=(NetworkService(protocol='icmp'),))
    packet_filter_set = set()
    packet_filter_set.add(packet_filter)
    set_size = len(packet_filter_set)
    assert set_size == 1
