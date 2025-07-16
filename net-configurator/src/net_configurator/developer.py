"""Developer processes rules from source and updates target."""

import logging

from net_configurator.discrepancy_finder import FilterDiscrepancyFinder
from net_configurator.discrepancy_finder import OwnerDiscrepancyFinder
from net_configurator.discrepancy_finder import RuleDiscrepancyFinder
from net_configurator.optimizer import Optimizer
from net_configurator.rules_source import ReaderInterface
from net_configurator.rules_source import RulesSource
from net_configurator.rules_target import ReaderWriterInterface
from net_configurator.rules_target import RulesTarget


class Developer:
    """Developer processes rules from source and updates target.

    It reads the desired state from the source and the existing state
    from the target, optimizes the desired state using an Optimizer,
    uses DiscrepancyFinders to decide on how to modify the target to
    match the desired state, and applies the changes to the target.
    """

    def __init__(self, source_handler: ReaderInterface, target_handler: ReaderWriterInterface) -> None:
        """Inits Developer with source and target interfaces."""
        self.__source = RulesSource(source_handler)
        self.__target = RulesTarget(target_handler)

    def process(self) -> None:  # noqa: C901
        """Changes target to match source."""
        logger = logging.getLogger(self.__class__.__name__)

        with self.__source:
            desired_rules = self.__source.read_all_rules()
            logger.info('%d rules read from source', len(desired_rules))
        with self.__target:
            existing_rules = self.__target.read_all_rules()
            existing_filters = self.__target.read_all_filters()
            existing_owners = self.__target.read_all_owners()
            logger.info('%d rules read from target', len(existing_rules))

            optimizer = Optimizer(desired_rules)
            optimizer.optimize()
            desired_rules = optimizer.get_rules()
            desired_filters = optimizer.get_filters()
            desired_owners = optimizer.get_owners()

            rule_discrepancy_finder = RuleDiscrepancyFinder(desired_rules, existing_rules)
            filter_discrepancy_finder = FilterDiscrepancyFinder(desired_filters, existing_filters)
            owner_discrepancy_finder = OwnerDiscrepancyFinder(desired_owners, existing_owners)

            for rule_identifier in rule_discrepancy_finder.get_elements_to_delete():
                self.__target.delete_rule(rule_identifier)
            for packet_filter_identifier in filter_discrepancy_finder.get_elements_to_delete():
                self.__target.delete_filter(packet_filter_identifier)
            for owner_identifier in owner_discrepancy_finder.get_elements_to_delete():
                self.__target.delete_owner(owner_identifier)

            for owner in owner_discrepancy_finder.get_elements_to_add():
                self.__target.add_owner(owner)
            for packet_filter in filter_discrepancy_finder.get_elements_to_add():
                self.__target.add_filter(packet_filter)
            for rule in rule_discrepancy_finder.get_elements_to_add():
                self.__target.add_rule(rule)

            self.__target.apply_changes()
        logger.info('Target successfully updated')
