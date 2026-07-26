"""Lightweight trusted profile adaptation and drift tracking."""

from dataclasses import dataclass, field
from typing import Any

_DEVIATION_FEATURES = (
    "login_hour_deviation",
    "unusual_resource_score",
    "session_duration_deviation",
    "resource_transition_rarity",
)


@dataclass(slots=True)
class _AdaptiveState:
    """Mutable recent-history state for one entity."""

    observations: int = 0
    trusted_updates: int = 0
    ewm_deviation: float = 0.0
    consecutive_shift: int = 0
    trusted_baseline: dict[str, float] = field(default_factory=dict)


class AdaptiveProfileTracker:
    """Apply gradual recent-history adaptation without learning anomalies."""

    def __init__(self, *, decay: float = 0.92) -> None:
        """Initialize an in-memory rolling state tracker."""

        self._decay = decay
        self._states: dict[str, _AdaptiveState] = {}

    def adjust(self, row: dict[str, Any]) -> tuple[dict[str, Any], str]:
        """Reduce established benign deviations and return current drift status."""

        entity_id = str(row["entity_id"])
        state = self._states.setdefault(entity_id, _AdaptiveState())
        adjusted = dict(row)
        for feature in _DEVIATION_FEATURES:
            recent = state.trusted_baseline.get(feature, 0.0)
            adjusted[feature] = max(0.0, float(row[feature]) - recent * 0.5)
        return adjusted, self._status(state)

    def observe(
        self,
        row: dict[str, Any],
        *,
        trusted: bool,
    ) -> str:
        """Update state only with trusted behavior and return drift status."""

        entity_id = str(row["entity_id"])
        state = self._states.setdefault(entity_id, _AdaptiveState())
        state.observations += 1
        deviation = sum(min(1.0, float(row[feature])) for feature in _DEVIATION_FEATURES) / len(
            _DEVIATION_FEATURES
        )
        state.ewm_deviation = self._decay * state.ewm_deviation + (1.0 - self._decay) * deviation
        if trusted:
            state.trusted_updates += 1
            for feature in _DEVIATION_FEATURES:
                current = float(row[feature])
                previous = state.trusted_baseline.get(feature, current)
                state.trusted_baseline[feature] = (
                    self._decay * previous + (1.0 - self._decay) * current
                )
            state.consecutive_shift = (
                state.consecutive_shift + 1
                if deviation >= 0.4
                else max(0, state.consecutive_shift - 1)
            )
        return self._status(state)

    def snapshot(self, entity_id: str) -> dict[str, object]:
        """Return serializable adaptive state for an entity."""

        state = self._states.get(entity_id, _AdaptiveState())
        return {
            "status": self._status(state),
            "observations": state.observations,
            "trusted_updates": state.trusted_updates,
            "ewm_deviation": round(state.ewm_deviation, 4),
            "window_strategy": "exponential_decay",
            "decay": self._decay,
        }

    @staticmethod
    def _status(state: _AdaptiveState) -> str:
        """Classify recent behavioral drift from sustained trusted changes."""

        if state.observations < 5:
            return "warming_up"
        if state.consecutive_shift >= 4 and state.ewm_deviation >= 0.35:
            return "drifting"
        if state.ewm_deviation >= 0.2:
            return "adapting"
        return "stable"
