"""Pluggable decision policies for the ReAct loop."""
import json
import re
from typing import Callable

from core.schema import ToolCall


class BasePolicy:
    def decide(self, memory, tools) -> tuple[str, ToolCall | None]:
        raise NotImplementedError


class HeuristicPolicy(BasePolicy):
    """A deterministic ReAct policy. Same loop shape as an LLM-driven agent."""

    def decide(self, memory, tools) -> tuple[str, ToolCall | None]:
        task = memory["task"]
        flow_id = task["flow_id"]

        if "detect_anomaly" not in memory:
            return ("Score the flow with the Isolation Forest detector.",
                    ToolCall("detect_anomaly", {"flow_id": flow_id}))

        det = memory["detect_anomaly"]
        if not det["is_anomaly"]:
            return ("Score is below threshold — no anomaly to investigate.",
                    ToolCall("write_report", {}))

        if "explain_flow" not in memory:
            return ("Anomaly confirmed. Identify the features driving the score.",
                    ToolCall("explain_flow", {"flow_id": flow_id, "top_k": 5}))

        if "correlate_flows" not in memory:
            return ("Look for related activity from the same source.",
                    ToolCall("correlate_flows", {"flow_id": flow_id}))

        if "threat_intel_lookup" not in memory:
            return ("Check the source IP against threat intelligence.",
                    ToolCall("threat_intel_lookup", {"ip": task["src_ip"]}))

        kb = memory.get("knowledge", [])
        if len(kb) == 0:
            sig = memory["explain_flow"]["signature"]
            return (f"Retrieve attack patterns matching: {sig}",
                    ToolCall("search_knowledge", {"query": sig, "k": 4}))

        if len(kb) == 1:
            top = kb[0]["docs"][0] if kb[0]["docs"] else None
            topic = top.title if top else "network anomaly"
            return (f"Retrieve remediation guidance for {topic}.",
                    ToolCall("search_knowledge",
                             {"query": f"mitigation containment response for {topic}",
                              "k": 3}))

        return ("Evidence complete — writing report.", ToolCall("write_report", {}))


class LLMPolicy(BasePolicy):
    """ReAct policy backed by any LLM.

    Pass a callable that takes a prompt string and returns the model's text.
    """

    SYSTEM = (
        "You are a network security analyst agent. You investigate suspicious flows "
        "using tools. At each turn respond with EXACTLY:\n"
        "Thought: <your reasoning>\n"
        "Action: <tool_name>\n"
        "Action Input: <json object>\n"
        "When you have enough evidence, use the write_report tool."
    )

    def __init__(self, call_llm: Callable[[str], str], max_retries: int = 2):
        self.call_llm = call_llm
        self.max_retries = max_retries

    def _build_prompt(self, memory, tools) -> str:
        tool_desc = "\n".join(
            f"- {t.name}: {t.description} params={list(t.parameters.keys())}"
            for t in tools
        )
        history = memory.get("trace", [])
        hist_txt = "\n".join(history[-12:]) if history else "(none)"
        return (
            f"{self.SYSTEM}\n\nAvailable tools:\n{tool_desc}\n\n"
            f"Task: {json.dumps(memory['task'])}\n\n"
            f"History:\n{hist_txt}\n\n"
            f"Respond now."
        )

    def decide(self, memory, tools) -> tuple[str, ToolCall | None]:
        prompt = self._build_prompt(memory, tools)
        for _ in range(self.max_retries + 1):
            text = self.call_llm(prompt) or ""
            thought = _extract(text, "Thought")
            action = _extract(text, "Action")
            raw_args = _extract(text, "Action Input") or "{}"
            if action:
                try:
                    args = json.loads(raw_args)
                except json.JSONDecodeError:
                    args = {}
                return (thought or "Thinking...", ToolCall(action.strip(), args))
        return ("LLM failed to produce a valid action; aborting.", None)


def _extract(text: str, label: str) -> str | None:
    m = re.search(rf"{label}\s*:\s*(.+)", text, re.IGNORECASE)
    if not m:
        return None
    return m.group(1).split("\n")[0].strip()