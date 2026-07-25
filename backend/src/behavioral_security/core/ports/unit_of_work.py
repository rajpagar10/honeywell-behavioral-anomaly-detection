"""Atomic application transaction contract."""

from types import TracebackType
from typing import Protocol, Self

from behavioral_security.core.ports.repositories import (
    AccessEventRepository,
    AlertRepository,
    AnalystFeedbackRepository,
    DetectionRepository,
    EntityProfileRepository,
)


class UnitOfWork(Protocol):
    """Coordinate repositories that must commit or roll back together."""

    events: AccessEventRepository
    profiles: EntityProfileRepository
    detections: DetectionRepository
    alerts: AlertRepository
    feedback: AnalystFeedbackRepository

    def __enter__(self) -> Self:
        """Open a transaction scope."""

        ...

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        """Roll back on failure and release transaction resources."""

        ...

    def commit(self) -> None:
        """Commit all changes in the current transaction."""

        ...

    def rollback(self) -> None:
        """Roll back all changes in the current transaction."""

        ...
