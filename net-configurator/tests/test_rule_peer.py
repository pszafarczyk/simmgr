"""Tests for RulePeer class from `net_configurator.rule` module."""

from ipaddress import IPv4Address
from ipaddress import IPv4Network

import pytest

from net_configurator.rule import RulePeer


def test_valid_ip_range() -> None:
    """Case where ip_low and ip_high are valid."""
    rule_peer = RulePeer(ip_low='192.168.1.1', ip_high='192.168.1.100')
    assert rule_peer.ip_low == IPv4Address('192.168.1.1')
    assert rule_peer.ip_high == IPv4Address('192.168.1.100')


def test_valid_network_address() -> None:
    """Case with valid network address and no range."""
    rule_peer = RulePeer(ip_low='10.0.0.0/8')
    assert rule_peer.ip_low == IPv4Network('10.0.0.0/8')
    assert rule_peer.ip_high is None


@pytest.mark.parametrize('ip_low, ip_high', [('1.1.1.1', None), ('2.2.2.2', '2.2.2.2')])
def test_single_address(ip_low: str, ip_high: str | None) -> None:
    """Single IP or one element range should have it in low with high set to None."""
    rule_peer = RulePeer(ip_low=ip_low, ip_high=ip_high)
    assert rule_peer.ip_low == IPv4Address(ip_low)
    assert rule_peer.ip_high is None


def test_reversed_range_raises() -> None:
    """RulePeer with reversed range raises ValueError."""
    higher_ip = '172.31.1.2'
    lower_ip = '172.31.1.1'
    with pytest.raises(ValueError, match='ip_high cannot be lower than ip_low'):
        RulePeer(ip_low=higher_ip, ip_high=lower_ip)


def test_range_with_network_in_ip_low_raises() -> None:
    """Range with network in ip_low raises ValueError."""
    net = '192.168.0.0/24'
    ip_high = '192.168.0.10'
    with pytest.raises(ValueError, match='Range is not possible when ip_low is network address'):
        RulePeer(ip_low=net, ip_high=ip_high)
