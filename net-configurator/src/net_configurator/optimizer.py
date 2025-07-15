"""Optimizer optimizes rules."""

from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule


class Optimizer:
    """Optimizes rules."""

    def __init__(self, rules: set[Rule]) -> None:
        """Stores input rules."""
        self.__rules = rules

    def optimize(self) -> None:
        """Optimizes rules, filters and owners."""

    def get_rules(self) -> set[Rule]:
        """Returns set of optimized rules."""
        return self.__rules

    def get_filters(self) -> set[PacketFilter]:
        """Returns set of optimized filters."""
        return {rule.packet_filter for rule in self.__rules}

    def get_owners(self) -> set[Owner]:
        """Returns set of optimized owners."""
        owner_lists = [rule.owners for rule in self.__rules]
        return {owner for owner_list in owner_lists for owner in owner_list}
