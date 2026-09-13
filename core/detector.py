# core/detector.py
"""Isolation Forest anomaly detector with robust-z explanations."""
import numpy as np
from sklearn.ensemble import IsolationForest

from config import FEATURES, CONTAMINATION, THRESHOLD_PCTL
from core.features import median_mad, top_deviations
from core.schema import AnomalyResult


class AnomalyDetector:
    def __init__(self, seed: int = 42):
        self.feature_names = FEATURES
        self.model = IsolationForest(
            n_estimators=200,
            max_samples="auto",
            contamination=CONTAMINATION,
            random_state=seed,
            n_jobs=-1,
        )
        self.threshold: float | None = None
        self.med: np.ndarray | None = None
        self.mad: np.ndarray | None = None

    # ---------- internals ----------
    def _matrix(self, flows) -> np.ndarray:
        return np.array(
            [[float(f.features[name]) for name in self.feature_names] for f in flows],
            dtype=float,
        )

    @staticmethod
    def _to_score(decision: np.ndarray) -> np.ndarray:
        """decision_function: >0 normal, <0 anomaly -> map to (0,1) via sigmoid."""
        return 1.0 / (1.0 + np.exp(decision))

    # ---------- public API ----------
    def fit(self, baseline_flows) -> "AnomalyDetector":
        """Train on BASELINE (normal) traffic only — a proper unsupervised setup."""
        X = self._matrix(baseline_flows)
        self.model.fit(X)
        self.med, self.mad = median_mad(X)

        train_scores = self._to_score(self.model.decision_function(X))
        self.threshold = float(np.percentile(train_scores, THRESHOLD_PCTL))
        return self

    def score_many(self, flows) -> dict[str, AnomalyResult]:
        X = self._matrix(flows)
        raw = self._to_score(self.model.decision_function(X))
        return {
            f.flow_id: AnomalyResult(
                flow_id=f.flow_id,
                score=round(float(s), 4),
                is_anomaly=bool(s >= self.threshold),
                threshold=round(self.threshold, 4),
            )
            for f, s in zip(flows, raw)
        }

    def score(self, flow) -> AnomalyResult:
        X = self._matrix([flow])
        s = float(self._to_score(self.model.decision_function(X))[0])
        return AnomalyResult(
            flow_id=flow.flow_id,
            score=round(s, 4),
            is_anomaly=bool(s >= self.threshold),
            threshold=round(self.threshold, 4),
        )

    def explain(self, flow, top_k: int = 5) -> list[dict]:
        return top_deviations(flow, self.med, self.mad, self.feature_names, top_k)