"""Tests for RuleFilter class from `net_configurator.rule` module."""

import pytest

from net_configurator.rule import NetworkService
from net_configurator.rule import RuleFilter


@pytest.mark.parametrize(
    'services, expected_identifier',
    [
        ([NetworkService(protocol='tcp', port_low=443)], 'X-e7d78205b66768e343b3fd5821fbe7d3ad7f31a6'),
        (
            [NetworkService(protocol='udp', port_low=514), NetworkService(protocol='udp', port_low=3000, port_high=3009)],
            'X-ae3d90c03575d5a758b91befc66919f1c4526b9c',
        ),
    ],
)
def test_rule_filter_has_correct_identifier(services: list[NetworkService], expected_identifier: str) -> None:
    """Identifier attribute is as expected."""
    rule_filter = RuleFilter(services)
    assert rule_filter.identifier == expected_identifier


def test_rule_filter_identifier_independent_of_order() -> None:
    """Filter's identifier should be independent of services order."""
    service_icmp = NetworkService(protocol='icmp')
    service_tcp = NetworkService(protocol='tcp', port_low=80)
    filter_icmp_tcp = RuleFilter([service_icmp, service_tcp])
    filter_tcp_icmp = RuleFilter([service_tcp, service_icmp])
    assert filter_icmp_tcp.identifier == filter_tcp_icmp.identifier
