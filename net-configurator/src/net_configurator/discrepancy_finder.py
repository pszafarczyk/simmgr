"""RuleDiscrepancyFinder finds differences between two rule sets."""

import logging

from net_configurator.rule import IdentifiedModelInterface


class BaseDiscrepancyFinder:
    """Finds differences between two sets."""

    def __init__(self, desired_elements: set[IdentifiedModelInterface], existing_elements: set[IdentifiedModelInterface]) -> None:
        """Inits BaseDiscrepancyFinder with element sets."""
        self.__desired_elements = desired_elements
        self.__existing_elements = existing_elements

    def get_elements_to_delete(self) -> set[str]:
        """Returns set of element identifiers that should be deleted."""
        undesired_elements = self.__existing_elements.difference(self.__desired_elements)
        to_delete = {element.identifier for element in undesired_elements}
        logging.getLogger(self.__class__.__name__).debug('%d elements should be deleted', len(to_delete))
        return to_delete

    def get_elements_to_add(self) -> set[IdentifiedModelInterface]:
        """Returns set of elements that should be added."""
        to_add = self.__desired_elements.difference(self.__existing_elements)
        logging.getLogger(self.__class__.__name__).debug('%d elements should be added', len(to_add))
        return to_add


class RuleDiscrepancyFinder(BaseDiscrepancyFinder):
    """Finds differences between two rule sets."""


class FilterDiscrepancyFinder(BaseDiscrepancyFinder):
    """Finds differences between two filter sets."""


class OwnerDiscrepancyFinder(BaseDiscrepancyFinder):
    """Finds differences between two owner sets."""
