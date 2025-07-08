"""RuleDiscrepancyFinder finds differences between two rule sets."""

from net_configurator.rule import Rule


class RuleDiscrepancyFinder:
    """Finds differences between two rule sets."""

    def __init__(self, desired_rules: set[Rule], existing_rules: set[Rule]) -> None:
        """Inits RuleDiscrepancyFinder with rule sets."""
        self.__desired_rules = desired_rules
        self.__existing_rules = existing_rules

    def get_rules_to_delete(self) -> set[str]:
        """Returns set of rule identifiers that should be deleted."""
        undesired_rules = self.__existing_rules.difference(self.__desired_rules)
        return {rule.identifier for rule in undesired_rules}

    def get_rules_to_add(self) -> set[Rule]:
        """Returns set of rules that should be added."""
        return self.__desired_rules.difference(self.__existing_rules)
