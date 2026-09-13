"""The ReAct loop: think -> act -> observe -> repeat."""
from config import MAX_AGENT_STEPS
from core.schema import Step, ToolCall


def _fmt_args(args: dict) -> str:
    return ", ".join(f"{k}={v!r}" for k, v in args.items())


class ReActAgent:
    def __init__(self, tools, policy, max_steps: int = MAX_AGENT_STEPS):
        self.tools = {t.name: t for t in tools}
        self.policy = policy
        self.max_steps = max_steps

    def run(self, ctx, flow_id: str):
        flow = ctx.flows_by_id[flow_id]
        memory = {
            "task": {
                "flow_id": flow_id,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
            },
            "trace": [],
        }
        steps: list[Step] = []

        for _ in range(self.max_steps):
            thought, call = self.policy.decide(memory, list(self.tools.values()))
            if thought:
                steps.append(Step("thought", thought))
                memory["trace"].append(f"Thought: {thought}")

            if call is None:
                break

            if call.name not in self.tools:
                obs = f"ERROR: unknown tool '{call.name}'"
                steps.append(Step("observation", obs))
                memory["trace"].append(f"Observation: {obs}")
                continue

            tool = self.tools[call.name]
            action_txt = f"{call.name}({_fmt_args(call.args)})"
            steps.append(Step("action", action_txt, tool=call.name))
            memory["trace"].append(f"Action: {action_txt}")

            try:
                result = tool.call(ctx, memory, **call.args)
                memory[call.name] = result
                obs = tool.observation(result)
            except Exception as exc:                       # noqa: BLE001
                obs = f"ERROR: {type(exc).__name__}: {exc}"
                memory[call.name] = {"error": obs}

            steps.append(Step("observation", obs))
            memory["trace"].append(f"Observation: {obs}")

            if call.name == "write_report" and "report" in memory:
                break

        report = memory.get("report")
        if report is not None:
            report.steps = steps
        return report, steps, memory