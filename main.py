"""CLI entry point.

    python main.py                 # run the demo
    python main.py eval            # print all metrics
    python main.py investigate F01234
    python main.py list            # show flagged flows
"""
import argparse
import sys

from config import RAG_TOP_K
from core.system import build_system

C = {
    "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
}


def c(text, color):
    return f"{C.get(color, '')}{text}{C['reset']}"


def rule(title=""):
    line = "─" * 74
    if title:
        print(f"\n{c(title.upper(), 'bold')}\n{c(line, 'dim')}")
    else:
        print(c(line, "dim"))


def render_steps(steps):
    icons = {
        "thought": (c("THOUGHT", "magenta"), "◆"),
        "action": (c("ACTION", "cyan"), "▶"),
        "observation": (c("OBSERVATION", "green"), "●"),
    }
    for s in steps:
        if s.kind in icons:
            label, icon = icons[s.kind]
            print(f"  {c(icon, 'dim')} {label}  {s.content}")


def render_report(report):
    if report is None:
        print(c("  No report produced.", "red"))
        return

    color = {"MALICIOUS": "red", "SUSPICIOUS": "yellow", "BENIGN": "green"}[report.verdict]

    print(f"\n  {c(report.verdict, color)}  {c(report.attack_type, 'bold')}")
    print(f"  {c('confidence', 'dim')} {report.confidence}")

    rule("evidence")
    ev = report.evidence
    print(f"  flow          {ev['flow_id']}")
    print(f"  path          {ev['path']}")
    print(f"  anomaly score {ev['anomaly_score']}  (threshold {ev['threshold']})")

    corr = ev.get("correlation") or {}
    if corr:
        print(f"  correlation   {corr.get('peer_flows')} peer flows, "
              f"{corr.get('flagged_flows')} flagged, "
              f"{corr.get('distinct_dst_ips')} dst IPs, "
              f"fan-out {corr.get('fan_out')}")

    ti = ev.get("threat_intel") or {}
    if ti:
        listed = c("LISTED", "red") if ti.get("listed") else c("clean", "green")
        print(f"  threat intel  {listed}  conf={ti.get('confidence')}  "
              f"{ti.get('categories')}")

    devs = ev.get("top_deviations", [])
    if devs:
        print(f"\n  {'feature':<24}{'value':>10}{'baseline':>12}{'dir':>7}{'z':>8}")
        for d in devs:
            bar_len = min(int(abs(d["z"]) * 3), 28)
            bar = c("█" * bar_len, "red" if abs(d["z"]) > 3 else "yellow")
            print(f"  {d['feature']:<24}{d['value']:>10.3f}{d['baseline']:>12.3f}"
                  f"{d['direction']:>7}{d['z']:>8.2f}  {bar}")

    if ev.get("signature"):
        print(f"\n  {c('signature', 'dim')}  {c(ev['signature'], 'cyan')}")

    rule("recommended actions")
    for r in report.recommendations:
        print(f"  → {r}")

    rule("references")
    for r in report.references:
        print(f"  · {r}")


def render_knowledge(memory):
    kb = memory.get("knowledge", [])
    if not kb:
        return
    rule("retrieval (RAG)")
    for i, entry in enumerate(kb, 1):
        print(f"  {c(f'query {i}', 'dim')}  {c(entry['query'], 'cyan')}")
        for d in entry["docs"]:
            print(f"      {d.score:>6.3f}  {d.doc_id}  {d.title}")
        print()


def cmd_demo(args):
    system = build_system(verbose=True)
    flagged = [f for f in system.attack_flows()
               if system.scores[f.flow_id].is_anomaly]

    target = args.flow_id or max(
        flagged, key=lambda f: system.scores[f.flow_id].score).flow_id
    flow = system.flows_by_id[target]

    rule("investigation target")
    print(f"  flow      {flow.flow_id}")
    print(f"  path      {flow.src_ip} → {flow.dst_ip}:{flow.dst_port}")
    print(f"  truth     {c(flow.label, 'dim')}  {c('(eval only)', 'dim')}")

    rule("agent trace")
    report, steps, memory = system.investigate(target)
    render_steps(steps)
    render_knowledge(memory)
    rule("incident report")
    render_report(report)

    rule()
    print(f"  {c(str(len(steps)) + ' steps', 'dim')}  ·  "
          f"{c(str(sum(1 for s in steps if s.kind == 'action')) + ' tool calls', 'dim')}")


def cmd_investigate(args):
    system = build_system()
    if args.flow_id not in system.flows_by_id:
        print(c(f"Unknown flow id: {args.flow_id}", "red"))
        sys.exit(1)
    flow = system.flows_by_id[args.flow_id]
    rule("investigation target")
    print(f"  flow      {flow.flow_id}")
    print(f"  path      {flow.src_ip} → {flow.dst_ip}:{flow.dst_port}")
    print(f"  truth     {c(flow.label, 'dim')}  {c('(eval only)', 'dim')}")
    rule("agent trace")
    report, steps, memory = system.investigate(args.flow_id)
    render_steps(steps)
    render_knowledge(memory)
    rule("incident report")
    render_report(report)


def cmd_list(args):
    system = build_system()
    flagged = sorted(
        (f for f in system.flows if system.scores[f.flow_id].is_anomaly),
        key=lambda f: -system.scores[f.flow_id].score,
    )
    rule(f"flagged flows ({len(flagged)})")
    print(f"  {'flow':<9}{'score':>8}  {'truth':<14}{'src':<17}→ dst:port")
    print(c("  " + "─" * 70, "dim"))
    for f in flagged[:args.limit]:
        s = system.scores[f.flow_id]
        truth = c(f.label, "red" if f.label != "normal" else "green")
        print(f"  {f.flow_id:<9}{s.score:>8.4f}  {truth:<23}"
              f"{f.src_ip:<17}→ {f.dst_ip}:{f.dst_port}")


def cmd_eval(args):
    from eval.evaluate import evaluate_detection, evaluate_retrieval, evaluate_agent

    system = build_system()

    rule("detection (held-out test split)")
    det = evaluate_detection(system)
    print(f"  precision          {c(det['precision'], 'green')}")
    print(f"  recall             {c(det['recall'], 'green')}")
    print(f"  f1                 {c(det['f1'], 'green')}")
    print(f"  false positive rt  {c(det['false_positive_rate'], 'yellow')}")
    print(f"  confusion          tp={det['tp']} fp={det['fp']} "
          f"tn={det['tn']} fn={det['fn']}  (n={det['n_test']})")
    print(f"\n  per-attack recall")
    for k, v in det["per_attack_recall"].items():
        bar = c("█" * int(v * 30), "green" if v > 0.8 else "yellow")
        print(f"    {k:<16}{v:>6.3f}  {bar}")

    rule("retrieval (RAG)")
    ret = evaluate_retrieval(system)
    print(f"  evaluated          {ret['evaluated']} detected attacks")
    print(f"  top-1 accuracy     {c(ret['top1_accuracy'], 'green')}")
    print(f"  top-{RAG_TOP_K} accuracy     {c(ret[f'top{RAG_TOP_K}_accuracy'], 'green')}")
    print(f"  knowledge base     {ret['kb_size']} documents")

    rule("agent (full ReAct loop)")
    ag = evaluate_agent(system)
    print(f"  investigated       {ag['investigated']} flagged attacks")
    print(f"  malicious verdict  {c(ag['malicious_verdict_rate'], 'green')}")
    print(f"  avg steps          {ag['avg_steps']}")
    print(f"  max steps          {ag['max_steps']}")


def main():
    p = argparse.ArgumentParser(
        description="Agentic AI network anomaly detection with RAG")
    sub = p.add_subparsers(dest="cmd")

    d = sub.add_parser("demo", help="run a full investigation with pretty output")
    d.add_argument("--flow-id", default=None)
    d.set_defaults(func=cmd_demo)

    i = sub.add_parser("investigate", help="investigate a specific flow")
    i.add_argument("flow_id")
    i.set_defaults(func=cmd_investigate)

    l = sub.add_parser("list", help="list flagged flows")
    l.add_argument("--limit", type=int, default=20)
    l.set_defaults(func=cmd_list)

    e = sub.add_parser("eval", help="print all evaluation metrics")
    e.set_defaults(func=cmd_eval)

    args = p.parse_args()
    if not args.cmd:
        args = p.parse_args(["demo"])
    args.func(args)


if __name__ == "__main__":
    main()