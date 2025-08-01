"""Module for parsing WatchGuard Firebox firewall rules into structured data."""

from dataclasses import dataclass
from dataclasses import field
import logging
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
    owners: tuple[str, ...] = field(default_factory=tuple)
    packet_filter: list[Filter] = field(default_factory=list)


class WatchguardParser:
    """RuleManager class for managing WatchGuard Firebox firewall rules."""

    @staticmethod
    def extract_owner_names(data: str) -> list[str]:
        """Extract all unique rule IDs."""
        logger = logging.getLogger(__name__)
        logger.debug('Extracting owner names from data')
        pattern = re.compile(r'X-[A-Za-z0-9-_]+')
        matches = []
        for line in data.splitlines():
            match = pattern.search(line)
            if match:
                matches.append(match.group(0))
        logger.info('Extracted %d owner names', len(matches))
        return matches

    @staticmethod
    def extract_filter_names(data: str) -> list[str]:
        """Extract all unique rule IDs."""
        logger = logging.getLogger(__name__)
        logger.debug('Extracting filter names from data')
        pattern = re.compile(r'X-[a-f0-9]{40}')
        matches = []
        for line in data.splitlines():
            match = pattern.search(line)
            if match:
                matches.append(match.group(0))
        logger.info('Extracted %d filter names', len(matches))
        return matches

    @staticmethod
    def extract_rule_names(data: str) -> list[str]:
        """Extract all unique rule IDs."""
        logger = logging.getLogger(__name__)
        logger.debug('Extracting rule names from data')
        pattern = re.compile(r'X-[a-f0-9]{40}')
        matches = []
        for line in data.splitlines():
            match = pattern.search(line)
            if match:
                matches.append(match.group(0))
        logger.info('Extracted %d rule names', len(matches))
        return matches

    @staticmethod
    def check_for_error(data: str) -> bool:
        """Parse a rule text into a structured dictionary of attributes."""
        logger = logging.getLogger(__name__)
        logger.debug('Checking for errors in data')
        if data:
            logger.debug('Data present, no errors found')
        return False

    @staticmethod
    def parse_rule(rule_text: str) -> RuleAttributes:
        """Parse a rule text into a structured dictionary of attributes.

        Args:
            rule_text (str): The input rule text to parse.
        """
        logger = logging.getLogger(__name__)
        logger.debug('Parsing rule text')
        cleaned_lines = WatchguardParser._clean_rule_lines(rule_text)
        logger.info('Successfully parsed rule into attributes')
        return WatchguardParser._extract_attributes(cleaned_lines)

    @staticmethod
    def parse_filter(data: str) -> dict[str, list[Filter]]:
        """Parse service lines into structured protocol/port dictionaries."""
        logger = logging.getLogger(__name__)
        logger.debug('Parsing filter data')
        filters = []
        lines = data.strip().split('\n')
        for line in lines:
            parsed = WatchguardParser._parse_filter_line(line)
            if parsed:
                filters.append(parsed.__dict__)
        logger.info('Parsed %d filters', len(filters))
        return {'services': filters}

    @staticmethod
    def _parse_network(network_text: str) -> Network:
        """Parse network."""
        logger = logging.getLogger(__name__)
        logger.debug('Parsing network %s', network_text)
        network_text = network_text.strip()
        ip_low = ip_high = None

        if '-' in network_text:
            ip_low, ip_high = network_text.split('-')
            ip_low, ip_high = ip_low.strip(), ip_high.strip()
            logger.debug('Parsed range network: %s - %s', ip_low, ip_high)
        elif '/' in network_text:
            ip_low = network_text
            logger.debug('Parsed CIDR network: %s', ip_low)
        else:
            ip_low = network_text
            logger.debug('Parsed single IP network: %s', ip_low)

        return Network(ip_low=ip_low, ip_high=ip_high)

    @staticmethod
    def _clean_rule_lines(rule_text: str) -> list[list[str]]:
        """Split rule text into lines and clean them.

        Args:
            rule_text (str): The input rule text to clean.
        """
        logger = logging.getLogger(__name__)
        logger.debug('Cleaning rule text lines')
        parsed_lines = [line.split(' : ') for line in rule_text.splitlines()]
        cleaned_lines = [[part.strip(' []') for part in line] for line in parsed_lines]
        logger.debug('Cleaned %d lines', len(cleaned_lines))
        return cleaned_lines

    @staticmethod
    def _valid_lines(cleaned_lines: list[list[str]]) -> list[list[str]]:
        """Filter out lines that are too short to process."""
        logger = logging.getLogger(__name__)
        logger.debug('Filtering valid lines')
        min_line_length = 2
        valid_lines = [line for line in cleaned_lines if len(line) >= min_line_length]
        logger.debug('Filtered %d valid lines from %d total', len(valid_lines), len(cleaned_lines))
        return valid_lines

    @staticmethod
    def _parse_rule_line(line: list[str], attributes: RuleAttributes, prev_key: str) -> str:  # noqa: C901
        """Parse rule line."""
        logger = logging.getLogger(__name__)
        logger.debug('Parsing rule line: %s', line)
        key, value = line[0], line[1]
        new_key = ''
        match key:
            case 'from alias list':
                attributes.sources.append(WatchguardParser._parse_network(value))
                new_key = 'from alias list'
                logger.debug('Added source network: %s', value)

            case 'to alias list':
                attributes.destinations.append(WatchguardParser._parse_network(value))
                new_key = 'to alias list'
                logger.debug('Added destination network: %s', value)

            case '':
                if prev_key == 'from alias list':
                    attributes.sources.append(WatchguardParser._parse_network(value))
                    new_key = prev_key
                    logger.debug('Appended source network: %s', value)

                if prev_key == 'to alias list':
                    attributes.destinations.append(WatchguardParser._parse_network(value))
                    new_key = prev_key
                    logger.debug('Appended destination network: %s', value)

            case 'service':
                attributes.filter_name = value
                new_key = 'service'
                logger.debug('Added filter name: %s', value)

            case 'Tags':
                attributes.owners = tuple([tag.strip() for tag in value.split(',') if value])
                new_key = 'Tags'
                logger.debug('Added owner tags: %s', attributes.owners)

        return new_key

    @staticmethod
    def _extract_attributes(cleaned_lines: list[list[str]]) -> RuleAttributes:
        """Extract rule attributes from cleaned lines into a structured dictionary.

        Args:
            cleaned_lines (list[list[str]]): list of cleaned line parts.
        """
        logger = logging.getLogger(__name__)
        logger.debug('Extracting attributes from %d cleaned lines', len(cleaned_lines))

        attributes = RuleAttributes()
        prev_key = ''

        for line in WatchguardParser._valid_lines(cleaned_lines):
            prev_key = WatchguardParser._parse_rule_line(line, attributes, prev_key)

        logger.info('Extracted attributes: %s', attributes)
        return attributes

    @staticmethod
    def _match_range(line: str) -> re.Match[str] | None:
        """Match range."""
        logger = logging.getLogger(__name__)
        logger.debug('Matching range in line: %s', line)

        pattern = re.compile(r'\(\d+\): service-range/protocol\((\w+)\):start-port\((\d+)\) end-port\((\d+)\)')
        match = pattern.match(line)
        if match:
            logger.debug('Range match found: %s', match.groups())

        return match

    @staticmethod
    def _match_single(line: str) -> re.Match[str] | None:
        """Match single."""
        logger = logging.getLogger(__name__)
        logger.debug('Matching single in line: %s', line)
        pattern = re.compile(r'\(\d+\): service-single/protocol\((\w+)\):(.+)')
        match = pattern.match(line)
        if match:
            logger.debug('Single match found: %s', match.groups())
        return match

    @staticmethod
    def _extract_range(match: re.Match[str]) -> Filter:
        """Extract range."""
        logger = logging.getLogger(__name__)
        logger.debug('Extracting range filter from match')
        filter_obj = Filter(protocol=match.group(1), port_low=match.group(2), port_high=match.group(3))
        logger.debug('Extracted range filter: %s', filter_obj)
        return filter_obj

    @staticmethod
    def _extract_single(match: re.Match[str]) -> Filter:
        """Extract single."""
        logger = logging.getLogger(__name__)
        logger.debug('Extracting single filter from match')
        protocol = match.group(1)
        details = match.group(2)
        port_low = port_high = None

        if protocol in {'tcp', 'udp'}:
            port_match = re.search(r'port\((\d+)\)', details)
            if port_match:
                port_low = port_match.group(1)
                logger.debug('Found port %s for protocol %s', port_low, protocol)
        elif protocol == 'icmp':
            logger.debug('ICMP protocol, no port extraction needed')
        filter_obj = Filter(protocol=protocol, port_low=port_low, port_high=port_high)
        logger.debug('Extracted single filter: %s', filter_obj)
        return filter_obj

    @staticmethod
    def _parse_filter_line(line: str) -> Filter | None:
        """Parse filter line."""
        logger = logging.getLogger(__name__)
        logger.debug('Parsing filter line: %s', line)
        line = line.strip()
        if not line.startswith('('):
            logger.debug('Invalid filter line format, skipping')
            return None

        if match := WatchguardParser._match_range(line):
            return WatchguardParser._extract_range(match)

        if match := WatchguardParser._match_single(line):
            return WatchguardParser._extract_single(match)

        logger.debug('No match found for filter line')
        return None
