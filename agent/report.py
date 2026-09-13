"""Turns agent memory into a structured IncidentReport."""
from core.schema import IncidentReport


def _top_attack_doc(memory):
    kb = memory.get("knowledge", [])
    if not kb:
        return None
    for d in kb[0]["docs"]:
        if d.doc_id.startswith("KB-0") and not d.doc_id.startswith("KB-1"):
            return d
    return kb[0]["docs"][0] if kb[0]["docs"] else None


def _mitigation_docs(memory):
    kb = memory.get("knowledge", [])
    if len(kb) < 2:
        return []
    return kb[1]["docs"]


def synthesize_report(ctx, memory) -> IncidentReport:
    flow_id = memory["task"]["flow_id"]
    flow = ctx.flows_by_id[flow_id]

    det = memory.get("detect_anomaly", {})
    exp = memory.get("explain_flow", {})
    corr = memory.get("correlate_flows", {})
    ti = memory.get("threat_intel_lookup", {})

    attack_doc = _top_attack_doc(memory)
    mitigations = _mitigation_docs(memory)

    anomaly_score = float(det.get("anomaly_score", 0.0))
    doc_score = float(attack_doc.score) if attack_doc else 0.0
    ti_conf = float(ti.get("confidence", 0.0)) if ti.get("listed") else 0.0

    confidence = round(0.45 * anomaly_score + 0.35 * doc_score + 0.20 * ti_conf, 3)

    if not det.get("is_anomaly"):
        verdict = "BENIGN"
        attack_type = "none"
        confidence = round(1.0 - anomaly_score, 3)
    elif ti.get("listed") or doc_score >= 0.45:
        verdict = "MALICIOUS"
        attack_type = attack_doc.title if attack_doc else "unknown anomaly"
    else:
        verdict = "SUSPICIOUS"
        attack_type = attack_doc.title if attack_doc else "unknown anomaly"

    evidence = {
        "flow_id": flow_id,
        "path": f"{flow.src_ip} -> {flow.dst_ip}:{flow.dst_port}",
        "anomaly_score": anomaly_score,
        "threshold": det.get("threshold"),
        "top_deviations": [
            {k: d[k] for k in ("feature", "value", "baseline", "direction", "z")}
            for d in exp.get("deviations", [])[:5]
        ],
        "signature": exp.get("signature", ""),
        "correlation": corr or {},
        "threat_intel": ti or {},
    }

    recommendations: list[str] = []
    for d in mitigations[:3]:
        recommendations.append(f"{d.title} ({d.doc_id}, score {d.score})")
    if corr.get("peer_flows", 0) > 100:
        recommendations.append(
            f"High fan-in: {corr['peer_flows']} flows from {flow.src_ip} "
            f"in {corr.get('window_s')}s — apply edge rate limit."
        )
    if ti.get("listed"):
        recommendations.append(
            f"Add {flow.src_ip} to the perimeter blocklist "
            f"(TI confidence {ti['confidence']})."
        )
    if not recommendations:
        recommendations.append("Monitor the source IP; no immediate action required.")

    references = [f"{d.doc_id} {d.title} ({d.score})" for d in mitigations[:2]]
    if attack_doc:
        references.insert(0, f"{attack_doc.doc_id} {attack_doc.title} ({attack_doc.score})")

    return IncidentReport(
        flow_id=flow_id,
        verdict=verdict,
        attack_type=attack_type,
        confidence=confidence,
        evidence=evidence,
        recommendations=recommendations,
        references=references,
    )