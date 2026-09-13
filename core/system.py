"""Composition root — wires data, detector, retriever, tools and agent together."""
from dataclasses import dataclass

import numpy as np

from config import SEED
from core.detector import AnomalyDetector
from core.schema import Flow, AnomalyResult
from datagen.generator import generate_dataset, THREAT_INTEL_IPS
from rag.retriever import Retriever
from agent.agent import ReActAgent
from agent.policy import HeuristicPolicy
from agent.tools import build_tools


@dataclass
class System:
    flows: list[Flow]
    train_flows: list[Flow]
    test_flows: list[Flow]
    flows_by_id: dict[str, Flow]
    detector: AnomalyDetector
    retriever: Retriever
    scores: dict[str, AnomalyResult]
    ti_feed: dict
    agent: ReActAgent

    def investigate(self, flow_id: str):
        return self.agent.run(self, flow_id)

    def attack_flows(self) -> list[Flow]:
        return [f for f in self.flows if f.label != "normal"]

    def normal_flows(self) -> list[Flow]:
        return [f for f in self.flows if f.label == "normal"]


def build_system(seed: int = SEED,
                 n_normal: int = 5000,
                 n_attack: int = 600,
                 policy=None,
                 verbose: bool = False) -> System:
    rng = np.random.default_rng(seed)
    flows = generate_dataset(rng, n_normal, n_attack)

    normal = [f for f in flows if f.label == "normal"]
    attacks = [f for f in flows if f.label != "normal"]
    rng.shuffle(normal)
    rng.shuffle(attacks)

    n_train = int(0.6 * len(normal))
    train_flows = normal[:n_train]
    test_flows = normal[n_train:] + attacks
    rng.shuffle(test_flows)

    if verbose:
        print(f"[system] generated {len(flows)} flows "
              f"({len(normal)} normal / {len(attacks)} attack)")
        print(f"[system] training detector on {len(train_flows)} baseline flows")

    detector = AnomalyDetector(seed=seed).fit(train_flows)

    retriever = Retriever()
    scores = detector.score_many(flows)

    ti_feed = {
        ip: {"categories": v["categories"], "confidence": v["confidence"]}
        for ip, v in THREAT_INTEL_IPS.items()
    }

    sys_obj = System(
        flows=flows,
        train_flows=train_flows,
        test_flows=test_flows,
        flows_by_id={f.flow_id: f for f in flows},
        detector=detector,
        retriever=retriever,
        scores=scores,
        ti_feed=ti_feed,
        agent=None,                                    # type: ignore[arg-type]
    )

    tools = build_tools()
    sys_obj.agent = ReActAgent(tools, policy or HeuristicPolicy())

    if verbose:
        flagged = sum(1 for s in scores.values() if s.is_anomaly)
        print(f"[system] threshold={detector.threshold:.4f} "
              f"flagged={flagged}/{len(flows)}")

    return sys_obj