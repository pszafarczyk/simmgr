"""Module for parsing WatchGuard Firebox firewall rules into structured data."""

from dataclasses import dataclass
from dataclasses import field
import re
from typing import Optional

from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class Network:
    """Represents a network range or single IP/CIDR."""

    ip_low: str
    ip_high: Optional[str]


@dataclass_json
@dataclass
class Filter:
    """Represents a filter with protocol and port information."""

    protocol: str
    port_low: Optional[str]
    port_high: Optional[str]


@dataclass_json
@dataclass
class RuleAttributes:
    """Represents the attributes of a firewall rule."""

    sources: list[Network] = field(default_factory=list)
    destinations: list[Network] = field(default_factory=list)
    filter_name: str = ''
    owners: list[str] = field(default_factory=list)
    packet_filter: list[Filter] = field(default_factory=list)


class WatchguardParser:
    """RuleManager class for managing WatchGuard Firebox firewall rules."""

    @staticmethod
    def extract_owner_names(data: str) -> list[str]:
        """Extract all unique rule IDs."""
        pattern = re.compile(r'X-[A-Za-z0-9-_]+')
        matches = []
        for line in data.splitlines():
            match = pattern.search(line)
            if match:
                matches.append(match.group(0))
        return matches

    @staticmethod
    def extract_filter_names(data: str) -> list[str]:
        """Extract all unique rule IDs."""
        pattern = re.compile(r'X-[a-f0-9]{40}')
        matches = []
        for line in data.splitlines():
            match = pattern.search(line)
            if match:
                matches.append(match.group(0))
        return matches

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
    def check_for_error(data: str) -> bool:
        """Parse a rule text into a structured dictionary of attributes."""
        if data:
            ...
        return False

    @staticmethod
    def parse_rule(rule_text: str) -> RuleAttributes:
        """Parse a rule text into a structured dictionary of attributes.

        Args:
            rule_text (str): The input rule text to parse.
        """
        cleaned_lines = WatchguardParser._clean_rule_lines(rule_text)
        return WatchguardParser._extract_attributes(cleaned_lines)

    @staticmethod
    def parse_filter(data: str) -> dict[str, list[Filter]]:
        """Parse service lines into structured protocol/port dictionaries."""
        filters = []
        lines = data.strip().split('\n')
        for line in lines:
            parsed = WatchguardParser._parse_filter_line(line)
            if parsed:
                filters.append(parsed.__dict__)
        return {'services': filters}

    @staticmethod
    def _parse_network(network_text: str) -> Network:
        """Parse network."""
        network_text = network_text.strip()
        ip_low = ip_high = None

        if '-' in network_text:
            ip_low, ip_high = network_text.split('-')
            ip_low, ip_high = ip_low.strip(), ip_high.strip()
        elif '/' in network_text:
            ip_low = network_text
        else:
            ip_low = network_text

        return Network(ip_low=ip_low, ip_high=ip_high)

    @staticmethod
    def _clean_rule_lines(rule_text: str) -> list[list[str]]:
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
    def _parse_rule_line(line: list[str], attributes: RuleAttributes, prev_key: str) -> str:  # noqa: C901
        """Parse rule line."""
        key, value = line[0], line[1]
        new_key = ''
        match key:
            case 'from alias list':
                attributes.sources.append(WatchguardParser._parse_network(value))
                new_key = 'from alias list'

            case '':
                if prev_key == 'from alias list':
                    attributes.sources.append(WatchguardParser._parse_network(value))
                    new_key = prev_key

                if prev_key == 'to alias list':
                    attributes.destinations.append(WatchguardParser._parse_network(value))
                    new_key = prev_key

            case 'to alias list':
                attributes.destinations.append(WatchguardParser._parse_network(value))
                new_key = 'to alias list'

            case 'service':
                attributes.filter_name = value
                new_key = 'service'

            case 'Tags':
                attributes.owners = [tag.strip() for tag in value.split(',')]
                new_key = 'Tags'

        return new_key

    @staticmethod
    def _extract_attributes(cleaned_lines: list[list[str]]) -> RuleAttributes:
        """Extract rule attributes from cleaned lines into a structured dictionary.

        Args:
            cleaned_lines (list[list[str]]): list of cleaned line parts.
        """
        attributes = RuleAttributes()
        prev_key = ''
        for line in WatchguardParser._valid_lines(cleaned_lines):
            prev_key = WatchguardParser._parse_rule_line(line, attributes, prev_key)
        return attributes

    @staticmethod
    def _match_range(line: str) -> re.Match[str] | None:
        """Match range."""
        pattern = re.compile(r'\(\d+\): service-range/protocol\((\w+)\):start-port\((\d+)\) end-port\((\d+)\)')
        return pattern.match(line)

    @staticmethod
    def _match_single(line: str) -> re.Match[str] | None:
        """Match single."""
        pattern = re.compile(r'\(\d+\): service-single/protocol\((\w+)\):(.+)')
        return pattern.match(line)

    @staticmethod
    def _extract_range(match: re.Match[str]) -> Filter:
        """Extract range."""
        return Filter(protocol=match.group(1), port_low=match.group(2), port_high=match.group(3))

    @staticmethod
    def _extract_single(match: re.Match[str]) -> Filter:
        """Extract single."""
        protocol = match.group(1)
        details = match.group(2)
        port_low = port_high = None

        if protocol in {'tcp', 'udp'}:
            port_match = re.search(r'port\((\d+)\)', details)
            if port_match:
                port_low = port_match.group(1)
        elif protocol == 'icmp':
            pass
        return Filter(protocol=protocol, port_low=port_low, port_high=port_high)

    @staticmethod
    def _parse_filter_line(line: str) -> Filter | None:
        """Parse filter line."""
        line = line.strip()
        if not line.startswith('('):
            return None

        if match := WatchguardParser._match_range(line):
            return WatchguardParser._extract_range(match)

        if match := WatchguardParser._match_single(line):
            return WatchguardParser._extract_single(match)

        return None
