"""Developer processes rules from source and updates target."""

import logging

from tenacity import before_sleep_log
from tenacity import retry_if_exception_type
from tenacity import RetryCallState
from tenacity import RetryError
from tenacity import Retrying
from tenacity import stop_after_attempt
from tenacity import stop_after_delay
from tenacity import wait_fixed

from net_configurator.base_exceptions import FatalError
from net_configurator.base_exceptions import RecoverableError
from net_configurator.discrepancy_finder import FilterDiscrepancyFinder
from net_configurator.discrepancy_finder import OwnerDiscrepancyFinder
from net_configurator.discrepancy_finder import RuleDiscrepancyFinder
from net_configurator.optimizer import Optimizer
from net_configurator.rule import Rule
from net_configurator.rules_source import ReaderFactoryInterface
from net_configurator.rules_source import ReaderInterface
from net_configurator.rules_source import RulesSource
from net_configurator.rules_target import ReaderWriterFactoryInterface
from net_configurator.rules_target import RulesTarget

SOURCE_RETRY_COUNT = 3
SOURCE_RETRY_TIMEOUT = 60
SOURCE_RETRY_DELAY = 10
# Watchguard blocks login for 3 minutes after admin user not logged out
TARGET_RETRY_COUNT = 3
TARGET_RETRY_TIMEOUT = 800
TARGET_RETRY_DELAY = 200


class SourceReaderError(Exception):
    """Exception raised when problems with reading rules from source."""


class Developer:
    """Developer processes rules from source and updates target.

    It reads the desired state from the source and the existing state
    from the target, optimizes the desired state using an Optimizer,
    uses DiscrepancyFinders to decide on how to modify the target to
    match the desired state, and applies the changes to the target.
    """

    def __init__(self, source_factory: ReaderFactoryInterface, target_factory: ReaderWriterFactoryInterface) -> None:
        """Inits Developer with source and target interface factories."""
        self.__source_factory = source_factory
        self.__target_factory = target_factory
        self.__source: RulesSource
        self.__recreate_target()

        self.source_retry_count = SOURCE_RETRY_COUNT
        self.source_retry_timeout = SOURCE_RETRY_TIMEOUT
        self.source_retry_delay = SOURCE_RETRY_DELAY
        self.target_retry_count = TARGET_RETRY_COUNT
        self.target_retry_timeout = TARGET_RETRY_TIMEOUT
        self.target_retry_delay = TARGET_RETRY_DELAY

        self.__logger = logging.getLogger(self.__class__.__name__)

    def __recreate_source(self) -> None:
        """(Re)creates rules source."""
        self.__source = RulesSource(self.__source_factory.create())

    def __recreate_target(self) -> None:
        """(Re)creates rules target."""
        self.__target = RulesTarget(self.__target_factory.create())

    def process(self) -> None:  # noqa: C901
        """Changes target to match source."""
        desired_rules = self.__read_source_rules()
        with self.__target:
            existing_rules = self.__target.read_all_rules()
            existing_filters = self.__target.read_all_filters()
            existing_owners = self.__target.read_all_owners()
            self.__logger.info('%d rules read from target', len(existing_rules))

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
        self.__logger.info('Target successfully updated')

    def __read_source_rules(self) -> set[Rule]:  # type: ignore[return]
        """Returns rules from source.

        In case of recoverable errors tries the operation source_retry_count times.

        Raises:
            SourceReaderError: When reading from source not possible.

        Returns:
            set[Rule]: Set of rules read from source.
        """

        def recreate_before_retry(retry_state: RetryCallState) -> None:  # noqa: ARG001
            self.__recreate_source()

        try:
            try:
                for attempt in Retrying(
                    stop=(stop_after_attempt(self.source_retry_count) | stop_after_delay(self.source_retry_timeout)),
                    wait=wait_fixed(self.source_retry_delay),
                    retry=retry_if_exception_type(RecoverableError),
                    reraise=True,
                    before_sleep=before_sleep_log(self.__logger, logging.WARNING),
                    before=recreate_before_retry,
                ):
                    with attempt, self.__source:
                        desired_rules = self.__source.read_all_rules()
                        self.__logger.info('%d rules read from source', len(desired_rules))
                        return desired_rules
            except RetryError:
                pass
        except (RecoverableError, FatalError) as e:
            raise SourceReaderError from e
