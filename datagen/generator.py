
# datagen/generator.py
"""Synthetic network flow generator. Zero downloads, fully reproducible."""
import numpy as np

from config import FEATURES
from core.schema import Flow

PROTO = {"tcp": 0.0, "udp": 1.0, "icmp": 2.0}

# Each profile: feature -> (mean, std, lo, hi)
# Signatures are deliberately distinct so the detector AND the retriever can tell them apart.
ATTACK_PROFILES = {
    "syn_flood": {
        "duration": (0.02, 0.02, 0.0, 0.2),
        "protocol": (0.0, 0.0, 0.0, 0.0),
        "src_bytes": (44, 20, 0, 200),
        "dst_bytes": (0, 0, 0, 0),
        "count": (480, 60, 200, 511),
        "srv_count": (470, 60, 200, 511),
        "serror_rate": (0.94, 0.05, 0.7, 1.0),
        "rerror_rate": (0.01, 0.01, 0.0, 0.1),
        "same_srv_rate": (0.98, 0.02, 0.8, 1.0),
        "diff_srv_rate": (0.02, 0.02, 0.0, 0.2),
        "dst_host_count": (240, 20, 180, 255),
        "dst_host_srv_count": (235, 25, 180, 255),
        "dst_host_serror_rate": (0.95, 0.05, 0.7, 1.0),
        "dst_port": 80,
    },
    "port_scan": {
        "duration": (0.05, 0.05, 0.0, 0.4),
        "protocol": (0.0, 0.0, 0.0, 0.0),
        "src_bytes": (60, 30, 0, 250),
        "dst_bytes": (20, 25, 0, 150),
        "count": (95, 30, 40, 200),
        "srv_count": (12, 8, 1, 45),
        "serror_rate": (0.05, 0.05, 0.0, 0.2),
        "rerror_rate": (0.88, 0.08, 0.6, 1.0),
        "same_srv_rate": (0.08, 0.06, 0.0, 0.3),
        "diff_srv_rate": (0.91, 0.07, 0.6, 1.0),
        "dst_host_count": (235, 22, 170, 255),
        "dst_host_srv_count": (18, 12, 1, 60),
        "dst_host_serror_rate": (0.06, 0.06, 0.0, 0.25),
        "dst_port": 22,
    },
    "slowloris": {
        "duration": (28.0, 6.0, 12.0, 45.0),
        "protocol": (0.0, 0.0, 0.0, 0.0),
        "src_bytes": (38, 15, 0, 140),
        "dst_bytes": (22, 14, 0, 120),
        "count": (120, 30, 60, 220),
        "srv_count": (118, 30, 60, 220),
        "serror_rate": (0.02, 0.03, 0.0, 0.15),
        "rerror_rate": (0.01, 0.02, 0.0, 0.1),
        "same_srv_rate": (0.99, 0.01, 0.9, 1.0),
        "diff_srv_rate": (0.01, 0.01, 0.0, 0.1),
        "dst_host_count": (42, 18, 10, 110),
        "dst_host_srv_count": (40, 18, 10, 110),
        "dst_host_serror_rate": (0.02, 0.03, 0.0, 0.15),
        "dst_port": 80,
    },
    "exfiltration": {
        "duration": (46.0, 14.0, 18.0, 90.0),
        "protocol": (0.0, 0.0, 0.0, 0.0),
        "src_bytes": (1850, 500, 700, 3600),
        "dst_bytes": (9400, 2400, 4200, 16000),
        "count": (2, 1.2, 0, 7),
        "srv_count": (2, 1.2, 0, 7),
        "serror_rate": (0.01, 0.02, 0.0, 0.1),
        "rerror_rate": (0.01, 0.02, 0.0, 0.1),
        "same_srv_rate": (0.97, 0.04, 0.8, 1.0),
        "diff_srv_rate": (0.03, 0.04, 0.0, 0.2),
        "dst_host_count": (8, 5, 1, 25),
        "dst_host_srv_count": (8, 5, 1, 25),
        "dst_host_serror_rate": (0.01, 0.02, 0.0, 0.1),
        "dst_port": 443,
    },
    "brute_force": {
        "duration": (0.9, 0.5, 0.05, 3.0),
        "protocol": (0.0, 0.0, 0.0, 0.0),
        "src_bytes": (180, 60, 40, 400),
        "dst_bytes": (70, 35, 0, 220),
        "count": (310, 60, 150, 470),
        "srv_count": (305, 60, 150, 470),
        "serror_rate": (0.82, 0.09, 0.55, 1.0),
        "rerror_rate": (0.03, 0.04, 0.0, 0.2),
        "same_srv_rate": (0.96, 0.03, 0.8, 1.0),
        "diff_srv_rate": (0.04, 0.03, 0.0, 0.2),
        "dst_host_count": (95, 25, 40, 170),
        "dst_host_srv_count": (215, 40, 110, 255),
        "dst_host_serror_rate": (0.83, 0.09, 0.55, 1.0),
        "dst_port": 22,
    },
    "http_flood": {
        "duration": (0.4, 0.25, 0.02, 1.6),
        "protocol": (0.0, 0.0, 0.0, 0.0),
        "src_bytes": (420, 120, 120, 900),
        "dst_bytes": (380, 140, 80, 950),
        "count": (430, 55, 220, 511),
        "srv_count": (420, 55, 220, 511),
        "serror_rate": (0.14, 0.07, 0.0, 0.35),
        "rerror_rate": (0.02, 0.03, 0.0, 0.12),
        "same_srv_rate": (0.97, 0.03, 0.85, 1.0),
        "diff_srv_rate": (0.03, 0.03, 0.0, 0.15),
        "dst_host_count": (225, 25, 150, 255),
        "dst_host_srv_count": (220, 28, 150, 255),
        "dst_host_serror_rate": (0.15, 0.08, 0.0, 0.4),
        "dst_port": 80,
    },
}

# A small pool of "attacker" IPs. Half are known to the threat-intel feed.
ATTACKER_IPS = [
    "185.220.101.44", "185.220.101.45", "45.155.205.233", "45.155.205.234",
    "103.75.190.11", "103.75.190.12", "91.240.118.172", "91.240.118.173",
    "198.98.51.189", "198.98.51.190", "194.26.135.77", "194.26.135.78",
]
THREAT_INTEL_IPS = {
    "185.220.101.44": {"categories": ["synflood"], "confidence": 0.91},
    "45.155.205.233": {"categories": ["portscan", "recon"], "confidence": 0.78},
    "103.75.190.11": {"categories": ["bruteforce"], "confidence": 0.84},
    "91.240.118.172": {"categories": ["exfiltration"], "confidence": 0.88},
    "198.98.51.189": {"categories": ["http_flood", "ddos"], "confidence": 0.81},
    "194.26.135.77": {"categories": ["slowloris"], "confidence": 0.73},
}

INTERNAL_SUBNET = "10.0.2."


def _clip(v, lo, hi):
    return float(max(lo, min(hi, v)))


def _sample(rng, spec):
    mean, std, lo, hi = spec
    return _clip(rng.normal(mean, std), lo, hi)  


def _profile_to_features(rng, profile) -> dict:
    return {
        name: _sample(rng, profile[name])
        for name in FEATURES
    }


def _normal_profile() -> dict:
    """A single 'normal traffic' profile — jittered per-flow."""
    return {
        "duration": (1.4, 0.9, 0.0, 9.0),
        "protocol": (0.0, 0.45, 0.0, 1.0),
        "src_bytes": (620, 380, 20, 3000),
        "dst_bytes": (780, 460, 0, 4000),
        "count": (3, 2, 0, 14),
        "srv_count": (3, 2, 0, 14),
        "serror_rate": (0.01, 0.02, 0.0, 0.12),
        "rerror_rate": (0.01, 0.02, 0.0, 0.12),
        "same_srv_rate": (0.96, 0.05, 0.6, 1.0),
        "diff_srv_rate": (0.03, 0.03, 0.0, 0.25),
        "dst_host_count": (18, 10, 1, 70),
        "dst_host_srv_count": (18, 10, 1, 70),
        "dst_host_serror_rate": (0.01, 0.02, 0.0, 0.12),
        "dst_port": None,   # random common port
    }


COMMON_PORTS = [80, 443, 22, 53, 8080, 3306]


def generate_dataset(rng, n_normal: int, n_attack: int,
                     base_ts: float = 1_700_000_000.0) -> list[Flow]:
    """Returns a shuffled list of Flow objects (normal + attacks)."""
    normal_profile = _normal_profile()
    attack_types = list(ATTACK_PROFILES.keys())

    specs = [("normal", None)] * n_normal
    specs += [("attack", attack_types[i % len(attack_types)]) for i in range(n_attack)]
    rng.shuffle(specs)

    flows: list[Flow] = []
    for i, (kind, atype) in enumerate(specs):
        ts = base_ts + i * float(rng.uniform(0.4, 2.4))
        if kind == "normal":
            profile = normal_profile
            feats = _profile_to_features(rng, profile)
            src = f"{INTERNAL_SUBNET}{int(rng.integers(2, 60))}"
            dst = f"{INTERNAL_SUBNET}{int(rng.integers(60, 200))}"
            port = int(rng.choice(COMMON_PORTS))
            label = "normal"
        else:
            profile = ATTACK_PROFILES[atype]
            feats = _profile_to_features(rng, profile)
            src = str(rng.choice(ATTACKER_IPS))
            dst = f"{INTERNAL_SUBNET}{int(rng.integers(2, 60))}"
            port = int(profile["dst_port"])
            label = atype

        flows.append(Flow(
            flow_id=f"F{i:05d}",
            src_ip=src,
            dst_ip=dst,
            dst_port=port,
            timestamp=ts,
            features=feats,
            label=label,
        ))
    return flows