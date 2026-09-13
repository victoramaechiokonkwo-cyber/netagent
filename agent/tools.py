"""Tool registry. Every tool is a plain function with a typed contract."""
from dataclasses import dataclass
from typing import Any, Callable

from config import RAG_TOP_K, CORRELATION_WINDOW_S
from core.features import build_signature


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, str]
    fn: Callable[..., Any]

    def call(self, ctx, memory, **kwargs):
        return self.fn(ctx, memory, **kwargs)

    def observation(self, result: Any) -> str:
        return self._format(result)

    def _format(self, result: Any) -> str:
        if isinstance(result, dict):
            return " · ".join(f"{k}={v}" for k, v in result.items())
        return str(result)


# --------------------------------------------------------------------------
# Tool implementations. Uniform signature: fn(ctx, memory, **kwargs) -> dict
# --------------------------------------------------------------------------

def t_detect_anomaly(ctx, memory, flow_id: str) -> dict:
    res = ctx.scores.get(flow_id) or ctx.detector.score(ctx.flows_by_id[flow_id])
    return {
        "flow_id": res.flow_id,
        "anomaly_score": res.score,
        "is_anomaly": res.is_anomaly,
        "threshold": res.threshold,
    }


def t_explain_flow(ctx, memory, flow_id: str, top_k: int = 5) -> dict:
    flow = ctx.flows_by_id[flow_id]
    devs = ctx.detector.explain(flow, top_k=top_k)
    sig, tokens = build_signature(devs)
    return {
        "deviations": devs,
        "signature": sig,
        "tokens": tokens,
        "summary": " | ".join(
            f"{d['feature']}={d['value']} ({d['direction']}, z={d['z']})"
            for d in devs[:3]
        ),
    }


def t_correlate_flows(ctx, memory, flow_id: str,
                      window_s: int = CORRELATION_WINDOW_S) -> dict:
    f = ctx.flows_by_id[flow_id]
    peers = [
        g for g in ctx.flows
        if g.src_ip == f.src_ip and abs(g.timestamp - f.timestamp) <= window_s
    ]
    flagged = [g for g in peers if ctx.scores[g.flow_id].is_anomaly]
    dst_ips = {g.dst_ip for g in peers}
    dst_ports = {g.dst_port for g in peers}
    return {
        "src_ip": f.src_ip,
        "window_s": window_s,
        "peer_flows": len(peers),
        "flagged_flows": len(flagged),
        "distinct_dst_ips": len(dst_ips),
        "distinct_dst_ports": len(dst_ports),
        "fan_out": round(len(peers) / max(len(dst_ips), 1), 1),
    }


def t_threat_intel_lookup(ctx, memory, ip: str) -> dict:
    hit = ctx.ti_feed.get(ip)
    if not hit:
        return {"ip": ip, "listed": False, "confidence": 0.0, "categories": []}
    return {
        "ip": ip,
        "listed": True,
        "confidence": hit["confidence"],
        "categories": hit["categories"],
        "source": "internal-ti-feed",
    }


def t_search_knowledge(ctx, memory, query: str, k: int = RAG_TOP_K) -> dict:
    docs = ctx.retriever.search(query, k=k)
    bucket = memory.setdefault("knowledge", [])
    bucket.append({"query": query, "docs": docs})
    return {
        "query": query,
        "returned": len(docs),
        "top": f"{docs[0].doc_id} {docs[0].title} ({docs[0].score})" if docs else "none",
    }


def t_write_report(ctx, memory) -> dict:
    from agent.report import synthesize_report
    report = synthesize_report(ctx, memory)
    memory["report"] = report
    return {
        "flow_id": report.flow_id,
        "verdict": report.verdict,
        "attack_type": report.attack_type,
        "confidence": report.confidence,
    }


def build_tools() -> list[Tool]:
    return [
        Tool("detect_anomaly",
             "Score a network flow with the Isolation Forest detector.",
             {"flow_id": "str"}, t_detect_anomaly),
        Tool("explain_flow",
             "Return the top features driving a flow's anomaly score.",
             {"flow_id": "str", "top_k": "int"}, t_explain_flow),
        Tool("correlate_flows",
             "Find related flows from the same source within a time window.",
             {"flow_id": "str", "window_s": "int"}, t_correlate_flows),
        Tool("threat_intel_lookup",
             "Check an IP against the internal threat-intelligence feed.",
             {"ip": "str"}, t_threat_intel_lookup),
        Tool("search_knowledge",
             "Semantic search over the security knowledge base (RAG).",
             {"query": "str", "k": "int"}, t_search_knowledge),
        Tool("write_report",
             "Synthesise the final incident report from collected evidence.",
             {}, t_write_report),
    ]