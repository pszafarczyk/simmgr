"""Module for parsing WatchGuard Firebox firewall rules into structured data."""

from dataclasses import dataclass
from dataclasses import field
import logging
import re
from typing import Any

from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class Network:
    """Represents a network range or single IP/CIDR."""

    ip_low: str
    ip_high: str | None


@dataclass_json
@dataclass
class Filter:
    """Represents a filter with protocol and port information."""

    protocol: str
    port_low: str | None
    port_high: str | None


@dataclass_json
@dataclass
class RuleAttributes:
    """Represents the attributes of a firewall rule."""

    sources: list[Network] = field(default_factory=list)
    destinations: list[Network] = field(default_factory=list)
    filter_name: str = ''
    owners: tuple[str, ...] = field(default_factory=tuple)
    packet_filter: dict[str, Filter] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:  # type: ignore [empty-body]
        """Empty implementation of to_dict dataclass_json implements it."""


class WatchguardParser:
    """RuleManager class for managing WatchGuard Firebox firewall rules."""

    def __init__(self) -> None:
        """Initialize WatchguardParser with logger."""
        self.__logger = logging.getLogger(self.__class__.__name__)

    def extract_owner_names(self, data: str) -> list[str]:
        """Extract all unique rule IDs."""
        self.__logger.debug('Extracting owner names from data')
        pattern = re.compile(r'X-[A-Za-z0-9-_]+')
        matches = []
        for line in data.splitlines():
            match = pattern.search(line)
            if match:
                matches.append(match.group(0))
        self.__logger.info('Extracted %d owner names', len(matches))
        return matches

    def extract_filter_names(self, data: str) -> list[str]:
        """Extract all unique rule IDs."""
        self.__logger.debug('Extracting filter names from data')
        pattern = re.compile(r'X-[a-f0-9]{40}')
        matches = []
        for line in data.splitlines():
            match = pattern.search(line)
            if match:
                matches.append(match.group(0))
        self.__logger.info('Extracted %d filter names', len(matches))
        return matches

    def extract_rule_names(self, data: str) -> list[str]:
        """Extract all unique rule IDs."""
        self.__logger.debug('Extracting rule names from data')
        pattern = re.compile(r'X-[a-f0-9]{40}')
        matches = []
        for line in data.splitlines():
            match = pattern.search(line)
            if match:
                matches.append(match.group(0))
        self.__logger.info('Extracted %d rule names', len(matches))
        return matches

    def check_for_error(self, data: str) -> bool:
        """Parse a rule text into a structured dictionary of attributes."""
        self.__logger.debug('Checking for errors in data')
        if data:
            self.__logger.debug('Data present, no errors found')
        return False

    def parse_rule(self, rule_text: str) -> RuleAttributes:
        """Parse a rule text into a structured dictionary of attributes.

        Args:
            rule_text (str): The input rule text to parse.
        """
        self.__logger.debug('Parsing rule text')
        cleaned_lines = self._clean_rule_lines(rule_text)
        self.__logger.info('Successfully parsed rule into attributes')
        return self._extract_attributes(cleaned_lines)

    def parse_filter(self, data: str) -> dict[str, Any]:
        """Parse service lines into structured protocol/port dictionaries."""
        self.__logger.debug('Parsing filter data')
        filters = []
        lines = data.strip().split('\n')
        for line in lines:
            parsed = self._parse_filter_line(line)
            if parsed:
                filters.append(parsed.__dict__)
        self.__logger.info('Parsed %d filters', len(filters))
        return {'services': filters}

    def _parse_network(self, network_text: str) -> Network:
        """Parse network."""
        self.__logger.debug('Parsing network %s', network_text)
        network_text = network_text.strip()
        ip_low = ip_high = None

        if '-' in network_text:
            ip_low, ip_high = network_text.split('-')
            ip_low, ip_high = ip_low.strip(), ip_high.strip()
            self.__logger.debug('Parsed range network: %s - %s', ip_low, ip_high)
        elif '/' in network_text:
            ip_low = network_text
            self.__logger.debug('Parsed CIDR network: %s', ip_low)
        else:
            ip_low = network_text
            self.__logger.debug('Parsed single IP network: %s', ip_low)

        return Network(ip_low=ip_low, ip_high=ip_high)

    def _clean_rule_lines(self, rule_text: str) -> list[list[str]]:
        """Split rule text into lines and clean them.

        Args:
            rule_text (str): The input rule text to clean.
        """
        self.__logger.debug('Cleaning rule text lines')
        parsed_lines = [line.split(' : ') for line in rule_text.splitlines()]
        cleaned_lines = [[part.strip(' []') for part in line] for line in parsed_lines]
        self.__logger.debug('Cleaned %d lines', len(cleaned_lines))
        return cleaned_lines

    def _valid_lines(self, cleaned_lines: list[list[str]]) -> list[list[str]]:
        """Filter out lines that are too short to process."""
        self.__logger.debug('Filtering valid lines')
        min_line_length = 2
        valid_lines = [line for line in cleaned_lines if len(line) >= min_line_length]
        self.__logger.debug('Filtered %d valid lines from %d total', len(valid_lines), len(cleaned_lines))
        return valid_lines

    def _parse_rule_line(self, line: list[str], attributes: RuleAttributes, prev_key: str) -> str:  # noqa: C901
        """Parse rule line."""
        self.__logger.debug('Parsing rule line: %s', line)
        key, value = line[0], line[1]
        new_key = ''
        match key:
            case 'from alias list':
                attributes.sources.append(self._parse_network(value))
                new_key = 'from alias list'
                self.__logger.debug('Added source network: %s', value)

            case 'to alias list':
                attributes.destinations.append(self._parse_network(value))
                new_key = 'to alias list'
                self.__logger.debug('Added destination network: %s', value)

            case '':
                if prev_key == 'from alias list':
                    attributes.sources.append(self._parse_network(value))
                    new_key = prev_key
                    self.__logger.debug('Appended source network: %s', value)

                if prev_key == 'to alias list':
                    attributes.destinations.append(self._parse_network(value))
                    new_key = prev_key
                    self.__logger.debug('Appended destination network: %s', value)

            case 'service':
                attributes.filter_name = value
                new_key = 'service'
                self.__logger.debug('Added filter name: %s', value)

            case 'Tags':
                attributes.owners = tuple([tag.strip() for tag in value.split(',') if value])
                new_key = 'Tags'
                self.__logger.debug('Added owner tags: %s', attributes.owners)

        return new_key

    def _extract_attributes(self, cleaned_lines: list[list[str]]) -> RuleAttributes:
        """Extract rule attributes from cleaned lines into a structured dictionary.

        Args:
            cleaned_lines (list[list[str]]): list of cleaned line parts.
        """
        self.__logger.debug('Extracting attributes from %d cleaned lines', len(cleaned_lines))

        attributes = RuleAttributes()
        prev_key = ''

        for line in self._valid_lines(cleaned_lines):
            prev_key = self._parse_rule_line(line, attributes, prev_key)

        self.__logger.info('Extracted attributes: %s', attributes)
        return attributes

    def _match_range(self, line: str) -> re.Match[str] | None:
        """Match range."""
        self.__logger.debug('Matching range in line: %s', line)

        pattern = re.compile(r'\(\d+\): service-range/protocol\((\w+)\):start-port\((\d+)\) end-port\((\d+)\)')
        match = pattern.match(line)
        if match:
            self.__logger.debug('Range match found: %s', match.groups())

        return match

    def _match_single(self, line: str) -> re.Match[str] | None:
        """Match single."""
        self.__logger.debug('Matching single in line: %s', line)
        pattern = re.compile(r'\(\d+\): service-single/protocol\((\w+)\):(.+)')
        match = pattern.match(line)
        if match:
            self.__logger.debug('Single match found: %s', match.groups())
        return match

    def _extract_range(self, match: re.Match[str]) -> Filter:
        """Extract range."""
        self.__logger.debug('Extracting range filter from match')
        filter_obj = Filter(protocol=match.group(1), port_low=match.group(2), port_high=match.group(3))
        self.__logger.debug('Extracted range filter: %s', filter_obj)
        return filter_obj

    def _extract_single(self, match: re.Match[str]) -> Filter:
        """Extract single."""
        self.__logger.debug('Extracting single filter from match')
        protocol = match.group(1)
        details = match.group(2)
        port_low = port_high = None

        if protocol in {'tcp', 'udp'}:
            port_match = re.search(r'port\((\d+)\)', details)
            if port_match:
                port_low = port_match.group(1)
                self.__logger.debug('Found port %s for protocol %s', port_low, protocol)
        elif protocol == 'icmp':
            self.__logger.debug('ICMP protocol, no port extraction needed')
        filter_obj = Filter(protocol=protocol, port_low=port_low, port_high=port_high)
        self.__logger.debug('Extracted single filter: %s', filter_obj)
        return filter_obj

    def _parse_filter_line(self, line: str) -> Filter | None:
        """Parse filter line."""
        self.__logger.debug('Parsing filter line: %s', line)
        line = line.strip()
        if not line.startswith('('):
            self.__logger.debug('Invalid filter line format, skipping')
            return None

        if match := self._match_range(line):
            return self._extract_range(match)

        if match := self._match_single(line):
            return self._extract_single(match)

        self.__logger.debug('No match found for filter line')
        return None
