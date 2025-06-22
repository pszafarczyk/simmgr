"""Classes for storing firewall rules."""

from ipaddress import IPv4Address
from ipaddress import IPv4Network
from typing import Annotated
from typing import Literal

from annotated_types import Len
from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator
from pydantic import ValidationInfo


class RuleFilter(BaseModel):
    """A protocol with (optionally) a port or a port range.

    Attributes:
        protocol (str): the protocol.
        port_low (int, optional): Port number or a low end of port range.
        port_high (int, optional): How end of port range.

    Raises:
        ValidationError: When data violates basic restrictions.
        ValueError: When ports are not valid.
    """

    protocol: Literal['tcp', 'udp', 'icmp']
    port_low: Annotated[int | None, Field(ge=0, le=65535)] = Field(default=None, validate_default=True)
    port_high: Annotated[int | None, Field(ge=0, le=65535)] = Field(default=None, validate_default=True)

    @field_validator('port_low', mode='after')
    @classmethod
    def tcpudp_has_port_low(cls, value: int | None, info: ValidationInfo) -> int | None:
        """Verifies port is specified for transport protocols and deletes for ICMP."""
        if info.data.get('protocol') == 'icmp':
            value = None
        elif value is None:
            msg = 'TCP/UDP requires a port number'
            raise ValueError(msg)
        return value

    @field_validator('port_high', mode='after')
    @classmethod
    def port_high_ge_low(cls, value: int | None, info: ValidationInfo) -> int | None:
        """Verifies port ranges and deletes port_high for non-ranges."""
        port_low = info.data.get('port_low')
        if port_low is None or value is None or value == port_low:
            value = None
        else:
            if value < port_low:
                msg = 'port_high cannot be lower than port_low'
                raise ValueError(msg)
            if port_low == 0:
                msg = 'Port 0 cannot be used in ranges'
                raise ValueError(msg)
        return value


class RulePeer(BaseModel):
    """Single IP address or a range or a network.

    Attributes:
        ip_low (IPv4Address | IPv4Network): Single or net IP or low end of range.
        ip_high (IPv4Address): How end of IP range.

    Raises:
        ValidationError: When data violates basic restrictions.
        ValueError: When IPs are not valid.
    """

    ip_low: IPv4Address | IPv4Network
    ip_high: IPv4Address | None = None

    @field_validator('ip_high', mode='after')
    @classmethod
    def ip_high_ge_low(cls, value: IPv4Address, info: ValidationInfo) -> IPv4Address | None:
        """Verifies IP ranges."""
        return_value: IPv4Address | None = value
        if value is not None:
            ip_low: IPv4Address | IPv4Network = info.data.get('ip_low')  # type: ignore[assignment]
            if isinstance(ip_low, IPv4Network):
                msg = 'Range is not possible when ip_low is network address'
                raise ValueError(msg)
            if value < ip_low:
                msg = 'ip_high cannot be lower than ip_low'
                raise ValueError(msg)
            if value == ip_low:
                return_value = None
        return return_value


class Rule(BaseModel):
    """A firewall rule.

    Attributes:
        identifier (str, optional): Rule name or id.
        sources (list[RulePeer]): List of source IP addresses.
        destinations (list[RulePeer]): List of destination IP addresses.
        filters (list[RuleFilter]): List of sockets.
        owners (set[str]): Owner tags.

    Raises:
        ValidationError: When data violates restrictions.
    """

    identifier: str | None = None
    sources: Annotated[list[RulePeer], Len(min_length=1)]
    destinations: Annotated[list[RulePeer], Len(min_length=1)]
    filters: Annotated[list[RuleFilter], Len(min_length=1)]
    owners: set[str] = set()
