from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]


class NetworkFlow(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str = "TCP"
    packets: int = Field(ge=1)
    bytes: int = Field(ge=1)
    duration_ms: float = Field(gt=0)
    tcp_flags: str = "ACK"


class ExplanationFactor(BaseModel):
    feature: str
    value: float
    contribution: float
    rationale: str


class DetectionResult(BaseModel):
    flow_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    threat_score: int
    severity: Severity
    is_anomaly: bool
    classification: str
    confidence: float
    explanation: list[ExplanationFactor]


class Overview(BaseModel):
    total_flows: int
    anomalies: int
    critical_alerts: int
    mean_threat_score: float
    model_status: str


class TimelineEvent(BaseModel):
    timestamp: datetime
    title: str
    severity: Severity
    source: str
    target: str
    score: int
    classification: str
