# core/schema.py
"""Typed data contracts shared across the whole system."""
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Flow:
    flow_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    timestamp: float
    features: dict[str, float]
    label: str = "normal"          # ground truth — used for eval only

    def to_dict(self) -> dict:
        d = asdict(self)
        d["features"] = {k: round(v, 4) for k, v in self.features.items()}
        return d


@dataclass
class AnomalyResult:
    flow_id: str
    score: float
    is_anomaly: bool
    threshold: float


@dataclass
class RetrievedDoc:
    doc_id: str
    title: str
    text: str
    score: float
    tags: list[str] = field(default_factory=list)


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass
class Step:
    kind: str                      # thought | action | observation | final
    content: str
    tool: str | None = None


@dataclass
class IncidentReport:
    flow_id: str
    verdict: str                   # BENIGN | SUSPICIOUS | MALICIOUS
    attack_type: str
    confidence: float
    evidence: dict[str, Any]
    recommendations: list[str]
    references: list[str]
    steps: list[Step] = field(default_factory=list)