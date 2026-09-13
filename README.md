# netagent — Agentic AI for Network Anomaly Detection (RAG)

A lightweight, fully offline research prototype. No large dataset downloads,
no embedding models, no GPU. Everything is synthetic and reproducible from a seed.

## Pipeline

```
synthetic flows ──► Isolation Forest ──► anomaly score + robust-z explanation
                                              │
                                              ▼
                        ┌───────────  ReAct agent loop  ───────────┐
                        │  think → act → observe → repeat          │
                        │                                          │
                        │  tools: detect_anomaly                   │
                        │         explain_flow                     │
                        │         correlate_flows                  │
                        │         threat_intel_lookup              │
                        │         search_knowledge  ◄── TF-IDF RAG │
                        │         write_report                     │
                        └──────────────────────────────────────────┘
                                              │
                                              ▼
                                    structured IncidentReport
```

## Layout

| Path | Purpose |
|---|---|
| `config.py` | All tunables (features, threshold, RAG params) in one place |
| `datagen/generator.py` | Synthetic flow generator + 6 attack profiles |
| `core/schema.py` | `Flow`, `AnomalyResult`, `Step`, `IncidentReport` dataclasses |
| `core/features.py` | Median/MAD baselines, robust-z, signature builder |
| `core/detector.py` | `AnomalyDetector` (Isolation Forest + explanation) |
| `core/system.py` | Composition root — wires everything together |
| `rag/docs.py` | 12-document security knowledge base |
| `rag/retriever.py` | TF-IDF retriever (swap for embeddings later) |
| `agent/tools.py` | Tool registry — 6 tools |
| `agent/policy.py` | `HeuristicPolicy` (offline) + `LLMPolicy` (drop in any model) |
| `agent/agent.py` | The ReAct loop |
| `agent/report.py` | Report synthesis from agent memory |
| `eval/evaluate.py` | Detection, retrieval and agent metrics |

## Quickstart

```bash
pip install -r requirements.txt

python main.py              # full demo: trace + retrieved docs + report
python main.py eval         # precision / recall / F1 / RAG accuracy
python main.py list         # top flagged flows
python main.py investigate F01234
```

## Using a real LLM as the policy

```python
from openai import OpenAI
from agent.policy import LLMPolicy
from core.system import build_system

client = OpenAI()

def call_llm(prompt: str) -> str:
    r = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
    )
    return r.choices[0].message.content

system = build_system(policy=LLMPolicy(call_llm))
report, steps, memory = system.investigate("F01234")
```

## Upgrading the RAG layer

`rag/retriever.py` is deliberately tiny. To move to embeddings:

```python
# pip install sentence-transformers
from sentence_transformers import SentenceTransformer

model = SentenceTransformer("all-MiniLM-L6-v2")   # 80 MB, runs on CPU
self.matrix = model.encode([d.indexed_text() for d in self.docs],
                           normalize_embeddings=True)
```

## Notes for the supervisor demo

- Training uses **baseline traffic only** — a proper unsupervised setup.
- The threshold is the 98th percentile of baseline scores (FP rate controlled by construction).
- Explanations are **robust z-scores** (median/MAD), not raw features.
- The RAG query is *generated* from the explanation, not hardcoded — the
  detector and the retriever are genuinely coupled.
- The agent's step budget, tool set and policy are all configurable.