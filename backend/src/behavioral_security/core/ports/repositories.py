"""Repository ports owned by the domain layer."""

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from behavioral_security.core.enums import AlertStatus
from behavioral_security.core.models.access_event import AccessEvent, GroundTruthRecord
from behavioral_security.core.models.alert import ClassifiedAlert
from behavioral_security.core.models.detection import DetectionResult
from behavioral_security.core.models.feedback import AnalystFeedback
from behavioral_security.core.models.profile import EntityProfile


class AccessEventRepository(Protocol):
    """Persistence contract for immutable operational access events."""

    def add(self, event: AccessEvent) -> bool:
        """Persist an event and return false when it already exists."""

        ...

    def get(self, event_id: UUID) -> AccessEvent | None:
        """Return an event by identifier."""

        ...

    def list_for_entity(
        self,
        entity_id: str,
        *,
        since: datetime | None = None,
        limit: int = 100,
    ) -> Sequence[AccessEvent]:
        """Return recent events for an entity in event-time order."""

        ...


class GroundTruthRepository(Protocol):
    """Evaluation-only persistence contract for synthetic labels."""

    def add(self, record: GroundTruthRecord) -> bool:
        """Persist a ground-truth record without exposing it to online services."""

        ...

    def get(self, event_id: UUID) -> GroundTruthRecord | None:
        """Return the evaluation label for an event."""

        ...


class EntityProfileRepository(Protocol):
    """Persistence contract for versioned behavioral profiles."""

    def get_current(self, entity_id: str) -> EntityProfile | None:
        """Return the latest profile for an entity."""

        ...

    def save(self, profile: EntityProfile) -> None:
        """Persist the current profile and its immutable version."""

        ...


class DetectionRepository(Protocol):
    """Persistence contract for versioned detection outputs."""

    def add(self, result: DetectionResult) -> None:
        """Persist a detection result and its component predictions."""

        ...

    def get_for_event(self, event_id: UUID) -> DetectionResult | None:
        """Return the fused detection result for an event."""

        ...


class AlertRepository(Protocol):
    """Persistence contract for classified SOC alerts."""

    def add(self, alert: ClassifiedAlert) -> None:
        """Persist a new alert and its explanation evidence."""

        ...

    def get(self, alert_id: UUID) -> ClassifiedAlert | None:
        """Return an alert by identifier."""

        ...

    def list_by_status(
        self,
        statuses: Sequence[AlertStatus],
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> Sequence[ClassifiedAlert]:
        """Return a deterministic page of alerts in descending creation order."""

        ...


class AnalystFeedbackRepository(Protocol):
    """Persistence contract for append-only analyst feedback."""

    def add(self, feedback: AnalystFeedback) -> None:
        """Persist one immutable analyst disposition."""

        ...

    def list_for_alert(self, alert_id: UUID) -> Sequence[AnalystFeedback]:
        """Return feedback history for an alert."""

        ...
