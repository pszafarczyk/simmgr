"""Tests for PacketFilter class from `net_configurator.rule` module."""

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
def test_rule_filter_has_correct_identifier(services: tuple[NetworkService, ...], expected_identifier: str) -> None:
    """Identifier attribute is as expected."""
    packet_filter = PacketFilter(services=services)
    assert packet_filter.identifier == expected_identifier


def test_rule_filter_identifier_independent_of_order() -> None:
    """Filter's identifier should be independent of services order."""
    service_icmp = NetworkService(protocol='icmp')
    service_tcp = NetworkService(protocol='tcp', port_low=80)
    filter_icmp_tcp = PacketFilter(services=(service_icmp, service_tcp))
    filter_tcp_icmp = PacketFilter(services=(service_tcp, service_icmp))
    assert filter_icmp_tcp.identifier == filter_tcp_icmp.identifier
