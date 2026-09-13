"""Detection + retrieval metrics over the held-out test split."""
import numpy as np

from config import RAG_TOP_K
from core.features import build_signature
from rag.docs import ATTACK_TO_DOC, ALL_DOCS


def _prf(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def evaluate_detection(system) -> dict:
    tp = fp = tn = fn = 0
    per_type: dict[str, list[int]] = {}

    for flow in system.test_flows:
        pred = system.scores[flow.flow_id].is_anomaly
        truth = flow.label != "normal"

        if truth and pred:
            tp += 1
        elif truth and not pred:
            fn += 1
        elif not truth and pred:
            fp += 1
        else:
            tn += 1

        if truth:
            bucket = per_type.setdefault(flow.label, [0, 0])
            bucket[1] += 1
            if pred:
                bucket[0] += 1

    precision, recall, f1 = _prf(tp, fp, fn)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "per_attack_recall": {
            k: round(v[0] / v[1], 3) for k, v in sorted(per_type.items())
        },
        "n_test": len(system.test_flows),
    }


def evaluate_retrieval(system, top_k: int = RAG_TOP_K) -> dict:
    hits = {1: 0, top_k: 0}
    total = 0
    misses: list[tuple[str, str, str]] = []

    for flow in system.attack_flows():
        if not system.scores[flow.flow_id].is_anomaly:
            continue
        expected = ATTACK_TO_DOC.get(flow.label)
        if expected is None:
            continue

        deviations = system.detector.explain(flow, top_k=5)
        signature, _ = build_signature(deviations)
        docs = system.retriever.search(signature, k=top_k)
        ids = [d.doc_id for d in docs]

        total += 1
        if ids and ids[0] == expected:
            hits[1] += 1
        if expected in ids:
            hits[top_k] += 1
        else:
            misses.append((flow.flow_id, flow.label, signature))

    return {
        "evaluated": total,
        "top1_accuracy": round(hits[1] / total, 4) if total else 0.0,
        f"top{top_k}_accuracy": round(hits[top_k] / total, 4) if total else 0.0,
        "example_misses": misses[:5],
        "kb_size": len(ALL_DOCS),
    }


def evaluate_agent(system, sample: int = 25) -> dict:
    attacks = [f for f in system.attack_flows()
               if system.scores[f.flow_id].is_anomaly][:sample]
    correct = 0
    step_counts = []

    for flow in attacks:
        report, steps, _ = system.investigate(flow.flow_id)
        step_counts.append(len(steps))
        if report and report.verdict == "MALICIOUS":
            correct += 1

    return {
        "investigated": len(attacks),
        "malicious_verdict_rate": round(correct / len(attacks), 4) if attacks else 0.0,
        "avg_steps": round(float(np.mean(step_counts)), 2) if step_counts else 0.0,
        "max_steps": int(max(step_counts)) if step_counts else 0,
    }