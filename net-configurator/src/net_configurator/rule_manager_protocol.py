"""Protocol defining the interface for managing rules on the firewall."""

from typing import Protocol
from rule import NamedRule

class RuleManagerProtocol(Protocol):
    """
    Protocol that specifies the interface for managing firewall rules.
    Implementations must provide methods to add, delete, move, modify rules,
    apply pending changes, and read currently managed rules.
    """

    def add_rules(self, rules: list[NamedRule]) -> None:
        """
        Add add Rule order to the queue.

        Args:
            rules (list[NamedRule]): A list of NamedRule objects to be added.
        """
        ...

    def delete_rules(self, names: list[str]) -> None:
        """
        Add delete Rule order to the queue.

        Args:
            names (list[str]): A list of rule names to delete.
        """
        ...

    def move_rules(self, rules_to_move: list[touple[str,int]]) -> None:
        """
        Add move Rule order to the queue.
     
        Each (name, index) pair specifies a rule and its target position
        after removal from its current location. 
        Rule already in the target position shoul be moved down.

        Args:
            rules_to_move (list[tuple[str, int]]): A list of rule names to be moved with the target position in the rule list (0-based).
        """       
        ...

    def modify_rules(self, rules: list[NamedRule]) -> None:
        """
        Add modify Rule order to the queue.

        Args:
            rules (list[NamedRule]): A list of NamedRule objects with updated attributes for modification.
        """
        ...

    def apply_changes(self) -> None:
        """
        Apply any pending orders int the queue to the firewall configuration.

        This commits additions, deletions, moves, and modifications.
        """
        ...

    def read_managed_rules(self) -> list[NamedRule]:
        """
        Retrieve the list of Rules currently managed by this manager.

        Returns:
            list[NamedRule]: A list of the currently managed NamedRule objects.
        """
        ...

