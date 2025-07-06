"""Tests for NetworkPeer class from `net_configurator.rule` module."""

from ipaddress import IPv4Address
from ipaddress import IPv4Network

from pydantic import ValidationError
import pytest

from net_configurator.rule import NetworkPeer


def test_valid_ip_range() -> None:
    """Case where ip_low and ip_high are valid."""
    rule_peer = NetworkPeer(ip_low='192.168.1.1', ip_high='192.168.1.100')
    assert rule_peer.ip_low == IPv4Address('192.168.1.1')
    assert rule_peer.ip_high == IPv4Address('192.168.1.100')


def test_valid_network_address() -> None:
    """Case with valid network address and no range."""
    rule_peer = NetworkPeer(ip_low='10.0.0.0/8')
    assert rule_peer.ip_low == IPv4Network('10.0.0.0/8')
    assert rule_peer.ip_high is None


@pytest.mark.parametrize('ip_low, ip_high', [('1.1.1.1', None), ('2.2.2.2', '2.2.2.2')])
def test_single_address(ip_low: str, ip_high: str | None) -> None:
    """Single IP or one element range should have it in low with high set to None."""
    rule_peer = NetworkPeer(ip_low=ip_low, ip_high=ip_high)
    assert rule_peer.ip_low == IPv4Address(ip_low)
    assert rule_peer.ip_high is None


def test_reversed_range_raises() -> None:
    """NetworkPeer with reversed range raises ValidationError."""
    higher_ip = '172.31.1.2'
    lower_ip = '172.31.1.1'
    with pytest.raises(ValidationError, match='ip_high cannot be lower than ip_low'):
        NetworkPeer(ip_low=higher_ip, ip_high=lower_ip)


def test_range_with_network_in_ip_low_raises() -> None:
    """Range with network in ip_low raises ValidationError."""
    net = '192.168.0.0/24'
    ip_high = '192.168.0.10'
    with pytest.raises(ValidationError, match='Range is not possible when ip_low is network address'):
        NetworkPeer(ip_low=net, ip_high=ip_high)


def test_is_address_network_when_network() -> None:
    """Is_address_network should return True when peer is network."""
    ip_low = IPv4Network('10.0.0.0/8')
    network_peer = NetworkPeer(ip_low=ip_low)
    result = network_peer.is_address_network()
    assert result


@pytest.mark.parametrize('ip_low, ip_high', [('10.0.0.1', None), ('10.0.0.1', '10.0.0.10')])
def test_is_address_network_when_not_network(ip_low: str, ip_high: str | None) -> None:
    """Is_address_network should return True when peer is single or range."""
    network_peer = NetworkPeer(ip_low=ip_low, ip_high=ip_high)
    result = network_peer.is_address_network()
    assert not result


def test_is_address_single_when_single() -> None:
    """Is_address_single should return True when peer is single IP."""
    ip_low = IPv4Address('10.0.0.1')
    network_peer = NetworkPeer(ip_low=ip_low)
    result = network_peer.is_address_single()
    assert result


@pytest.mark.parametrize('ip_low, ip_high', [('10.0.0.0/8', None), ('10.0.0.1', '10.0.0.10')])
def test_is_address_single_when_not_single(ip_low: str, ip_high: str | None) -> None:
    """Is_address_single should return False when peer is network or range."""
    network_peer = NetworkPeer(ip_low=ip_low, ip_high=ip_high)
    result = network_peer.is_address_single()
    assert not result


def test_is_address_range_when_range() -> None:
    """Is_address_range should return True when peer is range."""
    ip_low = IPv4Address('10.0.0.1')
    ip_high = IPv4Address('10.0.0.10')
    network_peer = NetworkPeer(ip_low=ip_low, ip_high=ip_high)
    result = network_peer.is_address_range()
    assert result


@pytest.mark.parametrize('ip_low', ['10.0.0.0/8', '10.0.0.1'])
def test_is_address_range_when_not_range(ip_low: str) -> None:
    """Is_address_range should return False when peer is network or single."""
    network_peer = NetworkPeer(ip_low=ip_low)
    result = network_peer.is_address_range()
    assert not result
