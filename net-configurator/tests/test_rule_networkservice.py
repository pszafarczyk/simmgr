"""Tests for NetworkService class from `net_configurator.rule` module."""

from pydantic import ValidationError
import pytest

from net_configurator.rule import NetworkService


@pytest.fixture(params=['tcp', 'udp'])
def transport_protocol(request: pytest.FixtureRequest) -> str:
    """Fixture returning protocols which use ports."""
    return str(request.param)


@pytest.mark.parametrize('protocol', ['icmp', 'tcp', 'udp'])
def test_valid_protocol(protocol: str) -> None:
    """Invocation with valid protocol should be successful."""
    packet_filter = NetworkService(protocol=protocol, port_low=22)
    assert packet_filter.protocol == protocol


@pytest.mark.parametrize('protocol', ['invalid', '', None])
def test_invalid_protocol_raises(protocol: str) -> None:
    """Invalid protocol should raise error."""
    with pytest.raises(ValidationError, match="Input should be 'tcp', 'udp' or 'icmp'"):
        NetworkService(protocol=protocol, port_low=0)


@pytest.mark.parametrize('port_low, port_high', [(None, None), (80, None), (443, 443), (8080, 8088)])
def test_icmp_ignores_ports(port_low: int | None, port_high: int | None) -> None:
    """ICMP should have both ports None."""
    packet_filter = NetworkService(protocol='icmp', port_low=port_low, port_high=port_high)
    assert packet_filter.port_low is None
    assert packet_filter.port_high is None


def test_tcpudp_without_port_raises(transport_protocol: str) -> None:
    """Invocation for TCP/UDP without port should raise error."""
    with pytest.raises(ValidationError, match='requires a port number'):
        NetworkService(protocol=transport_protocol)


def test_tcpudp_with_none_port_raises(transport_protocol: str) -> None:
    """Invocation for TCP/UDP without port should raise error."""
    with pytest.raises(ValidationError, match='requires a port number'):
        NetworkService(protocol=transport_protocol, port_low=None)


@pytest.mark.parametrize('port_low, port_high', [(0, None), (143, None), (65535, None), (0, 0), (993, 993)])
def test_tcpudp_with_single_port(transport_protocol: str, port_low: int | None, port_high: int | None) -> None:
    """Single port or same ports should have it in low with high set to None."""
    packet_filter = NetworkService(protocol=transport_protocol, port_low=port_low, port_high=port_high)
    assert packet_filter.port_low == port_low
    assert packet_filter.port_high is None


@pytest.mark.parametrize('port_low, port_high', [(5432, 5435), (60000, 65535)])
def test_tcpudp_with_port_range(transport_protocol: str, port_low: int, port_high: int) -> None:
    """Port range should have low and high ports set properly."""
    packet_filter = NetworkService(protocol=transport_protocol, port_low=port_low, port_high=port_high)
    assert packet_filter.port_low == port_low
    assert packet_filter.port_high == port_high


@pytest.mark.parametrize('port_low', [-1, 65536])
def test_tcpudp_invalid_port_low_raises(transport_protocol: str, port_low: int) -> None:
    """Invalid low port should raise error."""
    with pytest.raises(ValidationError, match='Input should be (greater|less) than or equal'):
        NetworkService(protocol=transport_protocol, port_low=port_low)


def test_tcpudp_invalid_port_high_raises(transport_protocol: str) -> None:
    """Invalid high port should raise error."""
    with pytest.raises(ValidationError, match='Input should be less than or equal'):
        NetworkService(protocol=transport_protocol, port_low=1, port_high=65536)


def test_tcpudp_range_with_zero_raises(transport_protocol: str) -> None:
    """Port range starting with 0 should raise error."""
    with pytest.raises(ValidationError, match='Port 0 cannot be used in ranges'):
        NetworkService(protocol=transport_protocol, port_low=0, port_high=21)


@pytest.mark.parametrize('port_low, port_high', [(636, 389), (20, 0)])
def test_inverted_range_raises(transport_protocol: str, port_low: int, port_high: int) -> None:
    """Port_low > port_high should raise error."""
    with pytest.raises(ValidationError, match='port_high cannot be lower than port_low'):
        NetworkService(protocol=transport_protocol, port_low=port_low, port_high=port_high)


@pytest.mark.parametrize('port_low, port_high', [(27017, None), (27017, 27018)])
def test_has_port_when_port_set(port_low: int, port_high: int | None) -> None:
    """Has_port should return True for single port or range."""
    network_service = NetworkService(protocol='tcp', port_low=port_low, port_high=port_high)
    result = network_service.has_port()
    assert result


def test_has_port_when_port_not_set() -> None:
    """Has_port should return False for protocol without port."""
    network_service = NetworkService(protocol='icmp')
    result = network_service.has_port()
    assert not result


def test_is_port_single_when_port_single() -> None:
    """Is_port_single should return True when single port set."""
    network_service = NetworkService(protocol='tcp', port_low=27017)
    result = network_service.is_port_single()
    assert result


@pytest.mark.parametrize('protocol, port_low, port_high', [('icmp', None, None), ('tcp', 27017, 27018)])
def test_is_port_single_when_port_not_single(protocol: str, port_low: int | None, port_high: int | None) -> None:
    """Is_port_single should return False when port range set."""
    network_service = NetworkService(protocol=protocol, port_low=port_low, port_high=port_high)
    result = network_service.is_port_single()
    assert not result


def test_is_port_range_when_port_range() -> None:
    """Is_port_range should return True when port range set."""
    network_service = NetworkService(protocol='tcp', port_low=27017, port_high=27018)
    result = network_service.is_port_range()
    assert result


@pytest.mark.parametrize('protocol, port_low', [('icmp', None), ('tcp', 27017)])
def test_is_port_range_when_port_not_range(protocol: str, port_low: int | None) -> None:
    """Is_port_range should return False when single port set."""
    network_service = NetworkService(protocol=protocol, port_low=port_low)
    result = network_service.is_port_range()
    assert not result
