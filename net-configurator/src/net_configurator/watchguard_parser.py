"""Module for parsing WatchGuard Firebox firewall rules into structured data."""

import re
from typing import Union, Optional
from dataclasses import dataclass

@dataclass
class Network:
    """Represents a network range or single IP/CIDR."""
    ip_low: str
    ip_high: str


@dataclass
class RuleAttributes:
    """Represents the attributes of a firewall rule."""
    sources: list[Network]
    destinations: list[Network]
    filter_name: str
    owners: list[str]


@dataclass
class Filter:
    """Represents a filter with protocol and port information."""
    protocol: str
    port_low: str
    port_high: str

class WatchguardParser:
    """RuleManager class for managing WatchGuard Firebox firewall rules."""

    @staticmethod
    def extract_rule_names(data: str) -> list[str]:
        """Extract all unique rule IDs."""
        pattern = re.compile(r'X-[a-f0-9]{40}')
        matches = []
        for line in data.splitlines():
            match = pattern.search(line)
            if match:
                matches.append(match.group(0))
        return matches

    @staticmethod
    def parse_network(network_text: str) -> Network:
        """Parse network."""
        network_text = network_text.strip()
        ip_low = ip_high = ''

        if '-' in network_text:
            ip_low, ip_high = network_text.split('-')
            ip_low, ip_high = ip_low.strip(), ip_high.strip()
        elif '/' in network_text:
            ip_low = network_text
        else:
            ip_low = network_text

        return Network(ip_low=ip_low, ip_high=ip_high)
    
    @staticmethod
    def parse_rule(rule_text: str) -> RuleAttributes: 
        """Parse a rule text into a structured dictionary of attributes.

        Args:
            rule_text (str): The input rule text to parse.
        """

        cleaned_lines = WatchguardParser.clean_rule_lines(rule_text)
        return WatchguardParser.extract_attributes(cleaned_lines)

    @staticmethod
    def clean_rule_lines(rule_text: str) -> list[list[str]]:
        """Split rule text into lines and clean them.

        Args:
            rule_text (str): The input rule text to clean.
        """
        parsed_lines = [line.split(' : ') for line in rule_text.splitlines()]
        return [[part.strip(' []') for part in line] for line in parsed_lines]

    @staticmethod
    def _valid_lines(cleaned_lines: list[list[str]]) -> list[list[str]]:
        """Filter out lines that are too short to process."""
        min_line_length = 2
        return [line for line in cleaned_lines if len(line) >= min_line_length]

    @staticmethod
    def _from_handler(key: str, value: str) -> list[list[str]]:
        """Filter out lines that are too short to process."""
    
    @staticmethod
    def _parse_rule_line(line: list[str], attributes: dict[str, Union[list[Network], list[str], str]],prev_key: str) -> str:
        """Parse rule line."""
        key, value = line[0], line[1]

        if key == 'from alias list':
            attributes['sources'].append(WatchguardParser.parse_network(value))
            return 'from alias list'

        elif key == '' and prev_key == 'from alias list':
            attributes['sources'].append(WatchguardParser.parse_network(value))
            return prev_key
        
        if key == 'to alias list':
            attributes['destinations'].append(WatchguardParser.parse_network(value))
            return 'to alias list'

        elif key == '' and prev_key == 'to alias list':
            attributes['destinations'].append(WatchguardParser.parse_network(value))
            return prev_key
        
        if key == 'service':
            attributes['filter_name'] = value
            return 'service'

        if key == 'Tags':
            attributes['owners'] = [tag.strip() for tag in value.split(',')]
            return 'Tags'

    @staticmethod
    def extract_attributes(cleaned_lines: list[list[str]]) -> RuleAttributes:
        """Extract rule attributes from cleaned lines into a structured dictionary.

        Args:
            cleaned_lines (list[list[str]]): list of cleaned line parts.
        """
        attributes = {'sources': [], 'destinations': [], 'filter_name': '', 'owners': []}
        prev_key = ''
        for line in WatchguardParser._valid_lines(cleaned_lines):
            prev_key = WatchguardParser._parse_rule_line(line, attributes, prev_key)
        return attributes

    @staticmethod
    def _match_range(line: str) -> Optional[re.Match[str]]:
        """Match range."""
        pattern = re.compile(r'\(\d+\): service-range/protocol\((\w+)\):start-port\((\d+)\) end-port\((\d+)\)')
        return pattern.match(line)

    @staticmethod
    def _match_single(line: str) -> Optional[re.Match[str]]:
        """Match single."""
        pattern = re.compile(r'\(\d+\): service-single/protocol\((\w+)\):(.+)')
        return pattern.match(line)

    @staticmethod
    def _extract_range(match: re.Match[str]) -> Filter:
        """Extract range."""
        return Filter(
            protocol = match.group(1),
            port_low = match.group(2),
            port_high = match.group(3)
        )

    @staticmethod
    def _extract_single(match: re.Match[str]) -> Filter:
        """Extract single."""
        protocol = match.group(1)
        details = match.group(2)
        port_low = port_high = ''

        if protocol in {'tcp', 'udp'}:
            port_match = re.search(r'port\((\d+)\)', details)
            if port_match:
                port_low = port_match.group(1)
        elif protocol == 'icmp':
            pass
        return Filter(protocol=protocol, port_low=port_low, port_high=port_high)

    @staticmethod
    def _parse_filter_line(line: str) -> Optional[Filter]:
        """Parse filter line."""
        line = line.strip()
        if not line.startswith('('):
            return None

        if match := WatchguardParser._match_range(line):
            return WatchguardParser._extract_range(match)

        if match := WatchguardParser._match_single(line):
            return WatchguardParser._extract_single(match)

        return None

    @staticmethod
    def parse_filter(data: str) -> list[Filter]:
        """Parse service lines into structured protocol/port dictionaries."""
        result = []
        lines = data.strip().split('\n')
        for line in lines:
            parsed = WatchguardParser._parse_filter_line(line)
            if parsed:
                result.append(parsed)
        return result
