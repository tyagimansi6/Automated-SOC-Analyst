"""Baseline anomaly scoring with a Joblib/scikit-learn integration stub."""

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from app.models.schemas import EventStatus, EventType, TelemetryEventRead

HIGH_RISK_THRESHOLD: float = 0.85
LOW_RISK_CEILING: float = 0.20

_HIGH_SEVERITY_EVENTS: frozenset[EventType] = frozenset(
    {
        EventType.LATERAL_MOVEMENT,
        EventType.AUTH_FAILURE,
        EventType.DATA_EXFILTRATION,
        EventType.MALWARE_DETECTED,
        EventType.PRIVILEGE_ESCALATION,
    },
)


@runtime_checkable
class ProbabilisticModel(Protocol):
    """Scikit-learn-style estimator expected from the ML artifact."""

    def predict_proba(self, X: Any) -> Any: ...


class AnomalyDetector:
    """Scores telemetry events in ``[0.0, 1.0]``.

    Uses baseline heuristics until ``load_trained_model`` attaches a Joblib
    scikit-learn estimator with ``predict_proba``.
    """

    def __init__(self) -> None:
        self._model: ProbabilisticModel | None = None
        self._model_path: str | None = None

    def predict_risk(self, event: TelemetryEventRead) -> float:
        """Return P(anomalous) for a telemetry event.

        Heuristic baseline: ``> 0.85`` for failed auth or lateral movement,
        otherwise ``< 0.20``. A loaded sklearn model overrides the heuristic.
        """
        if self._model is not None:
            return _clamp(self._predict_with_model(event))
        return _clamp(self._heuristic_risk(event))

    def load_trained_model(self, model_path: str) -> None:
        """Stub: load a Joblib-serialized scikit-learn estimator.

        ML teammate: replace the body with::

            import joblib
            self._model = joblib.load(model_path)

        The estimator must implement ``predict_proba(X)`` with shape
        ``(n_samples, n_classes)`` and the positive/anomalous class in the
        last column. Feature rows come from ``_vectorize``.
        """
        path = Path(model_path)
        if not path.is_file():
            raise FileNotFoundError(f"Trained model not found: {model_path}")
        self._model_path = str(path.resolve())
        self._model = None

    def _heuristic_risk(self, event: TelemetryEventRead) -> float:
        failed = event.status is EventStatus.FAILURE
        lateral = event.event_type is EventType.LATERAL_MOVEMENT
        if failed and lateral:
            return 0.98
        if failed or lateral:
            return 0.92
        if event.event_type in _HIGH_SEVERITY_EVENTS:
            return 0.90
        if event.status is EventStatus.BLOCKED:
            return 0.88
        if event.status is EventStatus.SUSPICIOUS:
            return 0.18
        return 0.08

    def _predict_with_model(self, event: TelemetryEventRead) -> float:
        if self._model is None:
            return self._heuristic_risk(event)
        probabilities = self._model.predict_proba(self._vectorize(event))
        return float(probabilities[0][-1])

    def _vectorize(self, event: TelemetryEventRead) -> list[list[float]]:
        """Stable numeric row for the forthcoming sklearn pipeline."""
        return [
            [
                1.0 if event.status is EventStatus.FAILURE else 0.0,
                1.0 if event.event_type is EventType.LATERAL_MOVEMENT else 0.0,
                1.0 if event.event_type is EventType.AUTH_FAILURE else 0.0,
                1.0 if event.event_type in _HIGH_SEVERITY_EVENTS else 0.0,
                float(list(EventType).index(event.event_type)),
                float(list(EventStatus).index(event.status)),
            ]
        ]


def _clamp(score: float) -> float:
    return max(0.0, min(1.0, score))
