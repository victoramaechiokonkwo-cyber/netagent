# core/features.py
"""Baseline statistics + human-readable deviation signatures."""
import numpy as np
from config import FEATURES


def median_mad(matrix: np.ndarray):
    """Robust location/scale. MAD is resistant to the very outliers we hunt."""
    med = np.median(matrix, axis=0)
    mad = np.median(np.abs(matrix - med), axis=0)
    return med, mad


def robust_z(vec: np.ndarray, med: np.ndarray, mad: np.ndarray) -> np.ndarray:
    scale = 1.4826 * mad
    scale = np.where(scale < 1e-6, 1e-6, scale)
    return (vec - med) / scale


def top_deviations(flow, med, mad, feature_names, top_k=5) -> list[dict]:
    vec = np.array([flow.features[f] for f in feature_names], dtype=float)
    z = robust_z(vec, med, mad)
    order = np.argsort(-np.abs(z))[:top_k]
    out = []
    for i in order:
        out.append({
            "feature": feature_names[i],
            "value": round(float(vec[i]), 4),
            "baseline": round(float(med[i]), 4),
            "z": round(float(z[i]), 2),
            "direction": "high" if z[i] > 0 else "low",
            "contribution": round(min(abs(float(z[i])) / 6.0, 1.0), 3),
        })
    return out


def build_signature(deviations: list[dict], min_abs_z: float = 1.5):
    """Turn deviations into a text query the retriever can match on.

    Returns (signature_string, tokens) e.g.
        "high serror_rate, high count, low duration"  ->  [...]
    """
    tokens = [f"{d['direction']} {d['feature']}"
              for d in deviations if abs(d["z"]) >= min_abs_z]
    if not tokens:
        tokens = [f"{d['direction']} {d['feature']}" for d in deviations[:3]]
    return ", ".join(tokens), tokens