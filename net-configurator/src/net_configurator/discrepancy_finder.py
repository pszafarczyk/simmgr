"""RuleDiscrepancyFinder finds differences between two rule sets."""

import logging
from typing import Generic
from typing import TypeVar

from net_configurator.rule import IdentifiedModelInterface
from net_configurator.rule import Owner
from net_configurator.rule import PacketFilter
from net_configurator.rule import Rule

T = TypeVar('T', bound=IdentifiedModelInterface)


class BaseDiscrepancyFinder(Generic[T]):
    """Finds differences between two sets."""

    def __init__(self, desired_elements: set[T], existing_elements: set[T]) -> None:
        """Inits BaseDiscrepancyFinder with element sets."""
        self.__desired_elements = desired_elements
        self.__existing_elements = existing_elements

    def get_elements_to_delete(self) -> set[str]:
        """Returns set of element identifiers that should be deleted."""
        undesired_elements = self.__existing_elements.difference(self.__desired_elements)
        to_delete = {element.identifier for element in undesired_elements}
        logging.getLogger(self.__class__.__name__).debug('%d elements should be deleted %s', len(to_delete), ','.join(to_delete))
        return to_delete

    def get_elements_to_add(self) -> set[T]:
        """Returns set of elements that should be added."""
        to_add = self.__desired_elements.difference(self.__existing_elements)
        to_add_identifiers = [element.identifier for element in to_add]
        logging.getLogger(self.__class__.__name__).debug('%d elements should be added %s', len(to_add), ','.join(to_add_identifiers))
        return to_add


class RuleDiscrepancyFinder(BaseDiscrepancyFinder[Rule]):
    """Finds differences between two rule sets."""


class FilterDiscrepancyFinder(BaseDiscrepancyFinder[PacketFilter]):
    """Finds differences between two filter sets."""


class OwnerDiscrepancyFinder(BaseDiscrepancyFinder[Owner]):
    """Finds differences between two owner sets."""
