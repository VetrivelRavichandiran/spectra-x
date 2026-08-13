from __future__ import annotations
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import random
from app.models.schemas import DetectionResult, NetworkFlow, TimelineEvent
from app.services.detector import detector


class InMemoryThreatStore:
    def __init__(self) -> None:
        self.detections: list[DetectionResult] = []
        self.seed_demo_data()

    @staticmethod
    def severity(score: int) -> str:
        if score >= 85: return "critical"
        if score >= 70: return "high"
        if score >= 45: return "medium"
        return "low"

    def ingest(self, flow: NetworkFlow) -> DetectionResult:
        scored = detector.score(flow)
        result = DetectionResult(
            flow_id=str(uuid4())[:8], timestamp=flow.timestamp, src_ip=flow.src_ip, dst_ip=flow.dst_ip,
            threat_score=scored.score, severity=self.severity(scored.score), is_anomaly=scored.anomaly,
            classification=scored.classification, confidence=scored.confidence, explanation=scored.explanation,
        )
        self.detections.insert(0, result)
        return result

    def seed_demo_data(self) -> None:
        rng = random.Random(17)
        now = datetime.now(timezone.utc)
        hostile = [
            ("10.13.37.8", "172.16.4.20", 22, 3, 180, 100, "SYN"),
            ("185.220.101.33", "10.0.2.15", 443, 2300, 1_400_000, 2400, "ACK"),
            ("10.0.1.41", "198.51.100.24", 4444, 120, 3_400_000, 7200, "PSH,ACK"),
            ("45.155.205.2", "10.0.2.15", 80, 1650, 700_000, 1900, "SYN"),
        ]
        for i in range(34):
            if i in {4, 11, 19, 28}:
                src, dst, port, packets, size, duration, flags = hostile.pop(0)
            else:
                src, dst, port = f"10.0.1.{rng.randint(2, 240)}", f"10.0.2.{rng.randint(2, 240)}", rng.choice([53, 80, 443, 8080])
                packets, size, duration, flags = rng.randint(4, 55), rng.randint(1200, 38000), rng.randint(250, 12000), "ACK"
            self.ingest(NetworkFlow(timestamp=now - timedelta(minutes=(34-i)*2), src_ip=src, dst_ip=dst, src_port=rng.randint(30000, 60000), dst_port=port, protocol="TCP", packets=packets, bytes=size, duration_ms=duration, tcp_flags=flags))

    def overview(self) -> dict:
        total = len(self.detections)
        anomalies = [d for d in self.detections if d.is_anomaly]
        return {"total_flows": total, "anomalies": len(anomalies), "critical_alerts": sum(d.severity == "critical" for d in anomalies), "mean_threat_score": round(sum(d.threat_score for d in self.detections) / max(total, 1), 1), "model_status": "online"}

    def timeline(self) -> list[TimelineEvent]:
        return [TimelineEvent(timestamp=d.timestamp, title=d.classification, severity=d.severity, source=d.src_ip, target=d.dst_ip, score=d.threat_score, classification=d.classification) for d in sorted(self.detections, key=lambda x: x.timestamp) if d.is_anomaly]

store = InMemoryThreatStore()
