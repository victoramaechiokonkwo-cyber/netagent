# config.py
"""Central configuration. No heavy datasets, no model downloads."""
from pathlib import Path

ROOT = Path(__file__).parent
ARTIFACT_DIR = ROOT / "artifacts"
ARTIFACT_DIR.mkdir(exist_ok=True)

SEED = 42

# 13 flow features (NSL-KDD style, but synthetic)
FEATURES = [
    "duration", "protocol", "src_bytes", "dst_bytes",
    "count", "srv_count", "serror_rate", "rerror_rate",
    "same_srv_rate", "diff_srv_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_serror_rate",
]

# Detector
CONTAMINATION = 0.02          # expected noise in baseline traffic
THRESHOLD_PCTL = 98.0         # decision threshold = 98th pct of baseline scores

# RAG
RAG_TOP_K = 4
TFIDF_NGRAMS = (1, 2)

# Agent
MAX_AGENT_STEPS = 10
CORRELATION_WINDOW_S = 600