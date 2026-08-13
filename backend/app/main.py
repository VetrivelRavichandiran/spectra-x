from __future__ import annotations

import csv
import io
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="SPECTRA-X Threat Intelligence API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

THREAT_TYPES = [
    "Behavioral Anomaly",
    "Port Scan",
    "Suspicious Exfiltration",
    "Brute Force Attempt",
    "Command & Control",
    "DNS Tunneling",
]

SOURCE_NETWORKS = ["10.0.1", "10.0.2", "192.168.1", "172.16.10"]
DESTINATION_NETWORKS = ["10.0.2", "10.0.3", "172.16.20", "192.168.10"]

incidents: list[dict[str, Any]] = []
telemetry: list[dict[str, Any]] = []


def severity_for_score(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 45:
        return "MEDIUM"
    return "LOW"


def random_ip(networks: list[str]) -> str:
    return f"{random.choice(networks)}.{random.randint(2, 254)}"


def create_incident(
    score: int | None = None,
    classification: str | None = None,
) -> dict[str, Any]:
    risk_score = score if score is not None else random.randint(38, 100)
    threat = classification or random.choice(THREAT_TYPES)

    now = datetime.now(timezone.utc)

    return {
        "id": uuid.uuid4().hex[:8],
        "time": now.isoformat(),
        "source": random_ip(SOURCE_NETWORKS),
        "destination": random_ip(DESTINATION_NETWORKS),
        "protocol": random.choice(["TCP", "UDP", "HTTP", "DNS", "TLS"]),
        "classification": threat,
        "score": risk_score,
        "severity": severity_for_score(risk_score),
        "confidence": random.randint(82, 99),
    }


def create_explanation(incident: dict[str, Any]) -> dict[str, Any]:
    score = incident["score"]

    return {
        "flow_id": incident["id"],
        "classification": incident["classification"],
        "confidence": incident["confidence"],
        "threat_score": score,
        "severity": incident["severity"],
        "features": [
            {
                "name": "bytes per packet",
                "sigma": round(random.uniform(4.2, 19.4), 2),
                "description": "Payload density differs from expected traffic.",
            },
            {
                "name": "bytes",
                "sigma": round(random.uniform(3.1, 8.9), 2),
                "description": "Transfer size deviates from the learned baseline.",
            },
            {
                "name": "duration ms",
                "sigma": round(random.uniform(2.8, 7.4), 2),
                "description": "Connection duration is outside normal behavior.",
            },
        ],
    }


def seed_data() -> None:
    if incidents:
        return

    for index in range(34):
        score = random.randint(22, 100)

        incident = create_incident(score=score)
        incident["time"] = (
            datetime.now(timezone.utc) - timedelta(minutes=(34 - index) * 2)
        ).isoformat()

        incidents.append(incident)
        telemetry.append(
            {
                "flow": index + 1,
                "score": score,
                "time": incident["time"],
            }
        )


def add_live_flow() -> None:
    """Simulates one newly observed flow whenever the dashboard refreshes."""
    score = random.randint(15, 100)
    incident = create_incident(score=score)

    incidents.insert(0, incident)
    del incidents[50:]

    telemetry.append(
        {
            "flow": telemetry[-1]["flow"] + 1 if telemetry else 1,
            "score": score,
            "time": incident["time"],
        }
    )
    del telemetry[:-40]


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/overview")
def get_overview() -> dict[str, Any]:
    seed_data()
    add_live_flow()

    anomaly_count = sum(1 for item in incidents if item["score"] >= 45)
    critical_count = sum(
        1 for item in incidents if item["severity"] == "CRITICAL"
    )
    mean_score = round(
        sum(item["score"] for item in incidents) / len(incidents),
        1,
    )

    return {
        "observed_flows": len(telemetry),
        "anomalies_detected": anomaly_count,
        "critical_alerts": critical_count,
        "mean_risk_score": mean_score,
        "risk_telemetry": telemetry,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/detections")
def get_detections(limit: int = 50) -> list[dict[str, Any]]:
    seed_data()
    return incidents[:limit]

@app.post("/api/analyze/csv")
async def analyze_csv(file: UploadFile = File(...)) -> dict[str, Any]:
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a CSV network-flow file.",
        )

    raw_file = await file.read()

    try:
        text = raw_file.decode("utf-8-sig")
        rows = list(csv.DictReader(io.StringIO(text)))
    except UnicodeDecodeError as error:
        raise HTTPException(
            status_code=400,
            detail="The CSV must use UTF-8 encoding.",
        ) from error

    if not rows:
        raise HTTPException(
            status_code=400,
            detail="The uploaded CSV has no data rows.",
        )

    seed_data()

    created: list[dict[str, Any]] = []

    for row in rows[:100]:
        # Basic demo scoring. Replace this later with your ML model's prediction.
        bytes_value = float(row.get("bytes", row.get("total_bytes", 0)) or 0)
        duration_value = float(
            row.get("duration_ms", row.get("duration", 0)) or 0
        )
        packets_value = float(row.get("packets", 1) or 1)

        score = 25
        score += min(int(bytes_value / 50000 * 35), 35)
        score += min(int(duration_value / 10000 * 20), 20)
        score += min(int(packets_value / 500 * 20), 20)
        score += random.randint(0, 20)
        score = max(1, min(score, 100))

        classification = (
            "Suspicious Exfiltration"
            if bytes_value > 500_000
            else "Behavioral Anomaly"
        )

        incident = create_incident(
            score=score,
            classification=classification,
        )

        incident["source"] = row.get("source_ip") or row.get("src_ip") or incident["source"]
        incident["destination"] = (
            row.get("destination_ip")
            or row.get("dst_ip")
            or incident["destination"]
        )
        incident["protocol"] = row.get("protocol") or incident["protocol"]

        incidents.insert(0, incident)
        created.append(incident)

        telemetry.append(
            {
                "flow": telemetry[-1]["flow"] + 1 if telemetry else 1,
                "score": score,
                "time": incident["time"],
            }
        )

    del incidents[50:]
    del telemetry[:-40]

    anomalies = sum(1 for item in created if item["score"] >= 45)

    return {
        "success": True,
        "filename": file.filename,
        "rows_processed": len(rows),
        "detections_created": len(created),
        "anomalies_detected": anomalies,
        "message": "CSV analysis completed. Dashboard data has been updated.",
    }