"""Explainable, locally runnable flow anomaly detector.

This demo uses IsolationForest trained on generated benign baseline data.  It is
purpose-built to be replaceable by a trained PyTorch/Sklearn pipeline later.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
import numpy as np
from sklearn.ensemble import IsolationForest
from app.models.schemas import ExplanationFactor, NetworkFlow

FEATURE_NAMES = ("bytes", "packets", "duration_ms", "dst_port", "bytes_per_packet", "packets_per_second")


@dataclass
class ScoredFlow:
    anomaly: bool
    score: int
    classification: str
    confidence: float
    explanation: list[ExplanationFactor]


class ThreatDetector:
    def __init__(self) -> None:
        self.model = IsolationForest(contamination=0.08, n_estimators=150, random_state=42)
        self._fit_baseline()

    def _fit_baseline(self) -> None:
        rng = np.random.default_rng(42)
        packets = rng.lognormal(mean=2.2, sigma=0.55, size=1500).clip(1, 350)
        duration = rng.lognormal(mean=6.3, sigma=0.85, size=1500).clip(20, 30000)
        bytes_per_packet = rng.normal(650, 180, size=1500).clip(40, 1500)
        values = np.column_stack((
            packets * bytes_per_packet,
            packets,
            duration,
            rng.choice([53, 80, 443, 8080, 22], size=1500, p=[.15, .3, .4, .1, .05]),
            bytes_per_packet,
            packets / (duration / 1000),
        ))
        self.model.fit(values)
        self.baseline_center = np.median(values, axis=0)
        self.baseline_scale = np.maximum(np.std(values, axis=0), 1)

    @staticmethod
    def vector(flow: NetworkFlow) -> np.ndarray:
        bpp = flow.bytes / max(flow.packets, 1)
        pps = flow.packets / max(flow.duration_ms / 1000, 0.001)
        return np.array([flow.bytes, flow.packets, flow.duration_ms, flow.dst_port, bpp, pps], dtype=float)

    def score(self, flow: NetworkFlow) -> ScoredFlow:
        vector = self.vector(flow)
        raw = float(-self.model.decision_function([vector])[0])
        anomaly = bool(self.model.predict([vector])[0] == -1)
        deviation = np.abs((vector - self.baseline_center) / self.baseline_scale)
        # Map only positive Isolation Forest outlier evidence to the ML risk score.
        # (Negative decision_function values are outliers; benign observations stay low.)
        risk = min(100, max(0, round(max(0, raw) * 260 + max(0, deviation.max() - 3) * 6)))
        classification = self.classify(flow, deviation, anomaly)
        if classification != "Benign":
            anomaly = True
            risk = max(risk, 58)
        confidence = round(min(0.99, 0.55 + max(deviation.max(), raw * 3) / 12), 2)
        indices = np.argsort(deviation)[-3:][::-1]
        rationales = {
            "bytes": "Transfer size deviates from the learned baseline.",
            "packets": "Packet count is unusual for a single flow.",
            "duration_ms": "Connection duration is outside normal behavior.",
            "dst_port": "Destination service is uncommon in the baseline.",
            "bytes_per_packet": "Payload density differs from expected traffic.",
            "packets_per_second": "Packet rate indicates possible scanning or flooding.",
        }
        explanation = [ExplanationFactor(feature=FEATURE_NAMES[i], value=round(float(vector[i]), 2), contribution=round(float(deviation[i]), 2), rationale=rationales[FEATURE_NAMES[i]]) for i in indices]
        return ScoredFlow(anomaly=anomaly, score=risk, classification=classification, confidence=confidence, explanation=explanation)

    @staticmethod
    def classify(flow: NetworkFlow, deviation: np.ndarray, anomaly: bool) -> str:
        if flow.dst_port in {22, 3389} and flow.packets < 10 and flow.duration_ms < 1500:
            return "Port Scan / Reconnaissance"
        if flow.packets / max(flow.duration_ms / 1000, .001) > 450 or flow.packets > 1000:
            return "Volumetric DDoS"
        if flow.dst_port in {4444, 5555, 1337} or (flow.bytes > 2_000_000 and flow.duration_ms < 10_000):
            return "Possible Data Exfiltration"
        if anomaly:
            return "Behavioral Anomaly"
        return "Benign"


detector = ThreatDetector()
