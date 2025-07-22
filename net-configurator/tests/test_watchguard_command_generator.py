"""Tests for WatchguardParser class from `net_configurator.watchguard_parser` module."""

from unittest.mock import patch

from pluggy import Result
import pytest

from net_configurator.rule import NetworkPeer, Owner
from net_configurator.rule import NetworkService
from net_configurator.rule import Rule
from net_configurator.rule import PacketFilter
from net_configurator.watchguard_command_generator import WatchguardCommandGenerator
from ipaddress import IPv4Address, IPv4Network


def to_ip_obj(ip_str):
    """Helper method for converting str to ips."""
    if '/' in ip_str:
        return IPv4Network(ip_str)

    return IPv4Address(ip_str)


@pytest.fixture
def network_peer_single():
    """Fixture for a single IP NetworkPeer."""
    return NetworkPeer(ip_low=to_ip_obj('192.168.1.1'))


@pytest.fixture
def network_peer_range():
    """Fixture for a range IP NetworkPeer."""
    return NetworkPeer(ip_low=IPv4Address('192.168.1.1'), ip_high=IPv4Address('192.168.1.10'))


@pytest.fixture
def network_peer_network():
    """Fixture for a network IP NetworkPeer."""
    return NetworkPeer(ip_low=IPv4Network('192.168.1.0/24'))


@pytest.fixture
def network_service_tcp_single():
    """Fixture for a TCP single port NetworkService."""
    return NetworkService(protocol='tcp', port_low=80)


@pytest.fixture
def network_service_tcp_range():
    """Fixture for a TCP port range NetworkService."""
    return NetworkService(protocol='tcp', port_low=80, port_high=90)


@pytest.fixture
def network_service_icmp():
    """Fixture for an ICMP NetworkService."""
    return NetworkService(protocol='icmp')


@pytest.fixture
def rule_filter(network_service_tcp_single):
    """Fixture for a PacketFilter with patched identifier."""
    with patch.object(PacketFilter, 'identifier', new_callable=lambda: 'test-filter-id'):
        return PacketFilter(root=(network_service_tcp_single,))


@pytest.fixture
def rule(network_peer_range, rule_filter):
    """Fixture for a Rule with patched identifier."""
    with patch.object(Rule, 'identifier', new_callable=lambda: 'test-rule-id'):
        return Rule(packet_filter=rule_filter, sources=(network_peer_range,), destinations=(network_peer_range,), owners=(Owner('X-1'), Owner('X-2')))


@pytest.mark.parametrize(
    'sources,destinations,services,owners,expected_policy_type_cmd,expected_policy_tag_cmd',
    [
        # Single IP, TCP single port, multiple owners
        (
            (NetworkPeer(ip_low=IPv4Address('192.168.1.1')),),
            (NetworkPeer(ip_low=IPv4Address('192.168.2.1')),),
            (NetworkService(protocol='tcp', port_low=80, port_high=80),),
            ('X-1', 'X-2'),
            'policy-type test-filter-id from host-ip 192.168.1.1 to host-ip 192.168.2.1',
            'policy-tag X-1 X-2',
        ),
        # IP range, TCP port range, single owner
        (
            (NetworkPeer(ip_low=IPv4Address('192.168.1.1'), ip_high=IPv4Address('192.168.1.10')),),
            (NetworkPeer(ip_low=IPv4Address('192.168.2.1'), ip_high=IPv4Address('192.168.2.10')),),
            (NetworkService(protocol='tcp', port_low=80, port_high=90),),
            ('X-1',),
            'policy-type test-filter-id from host-range 192.168.1.1 192.168.1.10 to host-range 192.168.2.1 192.168.2.10',
            'policy-tag X-1',
        ),
        # Network IP, ICMP, no owners
        (
            (NetworkPeer(ip_low=IPv4Network('192.168.1.0/24')),),
            (NetworkPeer(ip_low=IPv4Network('192.168.2.0/24')),),
            (NetworkService(protocol='icmp'),),
            tuple(),
            'policy-type test-filter-id from network-ip 192.168.1.0/24 to network-ip 192.168.2.0/24',
            'policy-tag ',
        ),
        # Mixed sources, UDP single port, multiple owners
        (
            (
                NetworkPeer(ip_low=IPv4Address('192.168.1.1')),
                NetworkPeer(ip_low=IPv4Network('192.168.3.0/24')),
            ),
            (NetworkPeer(ip_low=IPv4Address('192.168.2.1')),),
            (NetworkService(protocol='udp', port_low=53, port_high=53),),
            ('X-1', 'X-2', 'X-3'),
            'policy-type test-filter-id from host-ip 192.168.1.1 network-ip 192.168.3.0/24 to host-ip 192.168.2.1',
            'policy-tag X-1 X-2 X-3',
        ),
    ],
    ids=['single_ip_tcp_single_port', 'range_ip_tcp_port_range', 'network_ip_icmp', 'mixed_sources_udp_single_port'],
)
def test_add_rule_matrix(sources, destinations, services, owners, expected_policy_type_cmd, expected_policy_tag_cmd):
    """Test add_rule with various input combinations."""
    with (
        patch.object(Rule, 'identifier', new_callable=lambda: 'test-rule-id'),
        patch.object(PacketFilter, 'identifier', new_callable=lambda: 'test-filter-id'),
    ):
        rule_filter = PacketFilter(root=services)
        rule = Rule(packet_filter=rule_filter, sources=sources, destinations=destinations, owners=owners)
        expected_commands = ['config', 'policy', 'rule test-rule-id', expected_policy_type_cmd, expected_policy_tag_cmd, 'apply', 'exit', 'exit', 'exit']
        command_generator = WatchguardCommandGenerator()
        command_generator.add_rule(rule)
        result = command_generator.get_commands()
        assert result == expected_commands


@pytest.mark.parametrize(
    'services,expected_policy_type_cmd',
    [
        # Single TCP service
        ((NetworkService(protocol='tcp', port_low=80),), ['policy-type test-filter-id protocol tcp 80']),
        # TCP port range
        ((NetworkService(protocol='tcp', port_low=80, port_high=90),), ['policy-type test-filter-id protocol tcp port-range 80 90']),
        # ICMP service
        ((NetworkService(protocol='icmp'),), ['policy-type test-filter-id protocol icmp Any 255']),
        # Multiple services (TCP and UDP)
        (
            (NetworkService(protocol='tcp', port_low=80, port_high=80), NetworkService(protocol='udp', port_low=53, port_high=53)),
            ['policy-type test-filter-id protocol tcp 80', 'policy-type test-filter-id protocol udp 53'],
        ),
    ],
    ids=['tcp_single_port', 'tcp_port_range', 'icmp', 'multiple_services'],
)
def test_add_filter_matrix(services, expected_policy_type_cmd):
    """Test add_filter with various service configurations."""
    command_generator = WatchguardCommandGenerator()
    with patch.object(PacketFilter, 'identifier', new_callable=lambda: 'test-filter-id'):
        rule_filter = PacketFilter(root=services)
        expected_commands = ['config', 'policy'] + expected_policy_type_cmd + ['apply', 'exit', 'exit']
        command_generator.add_filter(rule_filter)
        result = command_generator.get_commands()
        assert result == expected_commands


def test_delete_rule():
    """Test the delete_rule method generates correct command."""
    command_generator = WatchguardCommandGenerator()
    command_generator.delete_rule('test-rule-id')
    result = command_generator.get_commands()
    assert result == ['config', 'policy', 'no rule test-rule-id', 'exit', 'exit']


def test_read_rules():
    """Test the read_rules method generates correct command."""
    command_generator = WatchguardCommandGenerator()
    command_generator.read_rules()
    result = command_generator.get_commands()
    assert result == ['show rule']


def test_read_owners():
    """Test the read_owners method generates correct command."""
    command_generator = WatchguardCommandGenerator()
    command_generator.read_owners()
    result = command_generator.get_commands()
    assert result == ['show policy-tag']


def test_read_rule():
    """Test the read_rule method generates correct command."""
    command_generator = WatchguardCommandGenerator()
    command_generator.read_rule('test-rule-id')
    result = command_generator.get_commands()
    assert result == ['show rule test-rule-id']


def test_add_owner():
    """Test the add_owner method generates correct commands."""
    owners = ('X-1', 'X-2')
    expected_commands = ['config', 'policy', 'policy-tag X-1 color 0xc0c0c0', 'policy-tag X-2 color 0xc0c0c0', 'exit', 'exit']
    command_generator = WatchguardCommandGenerator()
    command_generator.add_owner(owners)
    result = command_generator.get_commands()
    assert result == expected_commands


def test_delete_filter():
    """Test the delete_filter method generates correct command."""
    command_generator = WatchguardCommandGenerator()
    command_generator.delete_filter('test-filter-id')
    result = command_generator.get_commands()
    assert result == ['config', 'policy', 'no policy-type test-filter-id', 'exit', 'exit']


def test_read_filters():
    """Test the read_filters method generates correct command."""
    command_generator = WatchguardCommandGenerator()
    command_generator.read_filters()
    result = command_generator.get_commands()
    assert result == ['show policy-type']


def test_read_filter():
    """Test the read_filter method generates correct command."""
    command_generator = WatchguardCommandGenerator()
    command_generator.read_filter('test-filter-id')
    result = command_generator.get_commands()
    assert result == ['show policy-type test-filter-id']
