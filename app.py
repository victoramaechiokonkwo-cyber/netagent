import gradio as gr
from core.system import build_system

# Build the system once when the app starts
print("Building system...")
system = build_system()
print("System ready.")

def investigate_flow(flow_id: str):
    """Wraps your system's investigate method for Gradio."""
    # A simple input validation
    flow_id = flow_id.strip().upper()
    if not flow_id:
        return "Please enter a flow ID (e.g., F00042)."
    
    if flow_id not in system.flows_by_id:
        return f"Flow ID '{flow_id}' not found. Try one from the `list` command."
    
    # This is the core call to your existing agent logic!
    report, steps, memory = system.investigate(flow_id)
    
    # Format the trace for display
    output_text = f"### 🔍 Investigation for {flow_id}\n"
    output_text += f"**Path:** `{system.flows_by_id[flow_id].src_ip} → {system.flows_by_id[flow_id].dst_ip}:{system.flows_by_id[flow_id].dst_port}`\n\n"
    
    # Add the agent's ReAct trace
    output_text += "#### 🧠 Agent Trace\n"
    for step in steps:
        if step.kind == "thought":
            output_text += f"- **Thought:** {step.content}\n"
        elif step.kind == "action":
            output_text += f"- **Action:** `{step.content}`\n"
        elif step.kind == "observation":
            output_text += f"  - **Observation:** {step.content}\n"
    
    # Add the final report if it exists
    if report:
        output_text += f"\n#### 📋 Incident Report\n"
        output_text += f"- **Verdict:** {report.verdict}\n"
        output_text += f"- **Attack Type:** {report.attack_type}\n"
        output_text += f"- **Confidence:** {report.confidence}\n"
    
    return output_text

# Create the interface
demo = gr.Interface(
    fn=investigate_flow,
    inputs=gr.Textbox(label="Enter Flow ID", placeholder="e.g., F00042"),
    outputs=gr.Markdown(label="Investigation Result"),
    title="Network Anomaly Investigator",
    description="Enter a flow ID from the synthetic dataset to see the agent's investigation trace and final report.",
    examples=[["F00042"], ["F00100"], ["F00500"]]
)

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    demo.launch(server_name="0.0.0.0", server_port=port)