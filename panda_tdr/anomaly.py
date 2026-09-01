"""Unsupervised anomaly layer — rank source IPs by deviation from baseline.

Advisory only: it surfaces *unusual* sources (candidates worth an analyst's
look), never *malicious* verdicts. The deterministic detectors stay
authoritative; this is a second-opinion / early-warning signal that can catch
patterns the rules miss or catch late — using the weak signal across *many*
features that a single-threshold rule ignores.

Unsupervised (IsolationForest), so it needs no labels — but it is only
meaningful with VOLUME (many distinct sources). Below a floor it honestly
reports "insufficient data" instead of emitting noise. The intelligence is in
the features (attacker tempo, breadth, depth, cross-surface presence), not the
algorithm.
"""

from collections import Counter, namedtuple
from datetime import datetime

from sklearn.ensemble import IsolationForest

# The engineered per-source features the model reasons over. Order is the
# feature-vector order; keep it stable.
FEATURES = (
    "failed_attempts",     # total 4625 failed logons from this source
    "distinct_accounts",   # breadth — how many accounts were targeted
    "max_single_account",  # depth — most attempts against any one account
    "attempts_per_min",    # tempo — failed attempts per active minute
    "successes",           # 4624 successful logons from this source
    "distinct_hosts",      # how many hosts it touched
    "cowrie_events",        # honeypot events from this source
    "cowrie_commands",      # commands it ran on the honeypot
)

# Loopback is not an attacker surface — excluded from the baseline (the same
# call the brute/spray detector makes).
_LOOPBACK = frozenset({"::1", "127.0.0.1"})

# Below this many distinct non-loopback sources an unsupervised model is
# meaningless; report insufficient data rather than inventing outliers.
MIN_SOURCES = 8

SourceFeatures = namedtuple("SourceFeatures", ("src_ip",) + FEATURES)
AnomalyCandidate = namedtuple("AnomalyCandidate", "src_ip score is_outlier features")
AnomalyResult = namedtuple("AnomalyResult", "candidates n_sources insufficient")


def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def extract_features(failed, success, cowrie):
    """Aggregate the telemetry into one engineered feature vector per source IP.

    Loopback and source-less records are skipped. Returns list[SourceFeatures].
    """
    per = {}

    def g(ip):
        return per.setdefault(ip, {
            "accounts": Counter(), "fstamps": [], "hosts": set(),
            "successes": 0, "cowrie_events": 0, "cowrie_commands": 0,
        })

    for r in failed:
        if not r.src_ip or r.src_ip in _LOOPBACK:
            continue
        d = g(r.src_ip)
        d["accounts"][r.username] += 1
        d["fstamps"].append(r.timestamp)
        if r.host:
            d["hosts"].add(r.host)

    for r in success:
        if not r.src_ip or r.src_ip in _LOOPBACK:
            continue
        d = g(r.src_ip)
        d["successes"] += 1
        if r.host:
            d["hosts"].add(r.host)

    for r in cowrie:
        ip = getattr(r, "src_ip", None)
        if not ip or ip in _LOOPBACK:
            continue
        d = g(ip)
        d["cowrie_events"] += 1
        if getattr(r, "eventid", None) == "cowrie.command.input":
            d["cowrie_commands"] += 1

    out = []
    for ip, d in per.items():
        failed_attempts = sum(d["accounts"].values())
        stamps = sorted(d["fstamps"])
        span = ((_parse(stamps[-1]) - _parse(stamps[0])).total_seconds()
                if len(stamps) >= 2 else 0.0)
        minutes = max(span / 60.0, 1.0)  # avoid div-by-zero; sub-minute bursts -> 1
        out.append(SourceFeatures(
            src_ip=ip,
            failed_attempts=failed_attempts,
            distinct_accounts=len(d["accounts"]),
            max_single_account=max(d["accounts"].values(), default=0),
            attempts_per_min=round(failed_attempts / minutes, 3),
            successes=d["successes"],
            distinct_hosts=len(d["hosts"]),
            cowrie_events=d["cowrie_events"],
            cowrie_commands=d["cowrie_commands"],
        ))
    return out


def rank(snap, top_k=None, min_sources=MIN_SOURCES, random_state=0):
    """Rank sources by anomaly (most anomalous first).

    Returns an AnomalyResult. When fewer than `min_sources` distinct sources
    exist, `insufficient` is True and `candidates` is empty — the honest signal
    that there isn't enough population to baseline against (as on the tiny demo
    snapshot; the layer is meant for a larger real capture). `score` is higher
    for more anomalous sources; `is_outlier` is IsolationForest's own call.
    """
    feats = extract_features(snap["failed"], snap["success"], snap["cowrie"])
    if len(feats) < min_sources:
        return AnomalyResult([], len(feats), True)

    matrix = [[getattr(f, name) for name in FEATURES] for f in feats]
    clf = IsolationForest(random_state=random_state, contamination="auto")
    clf.fit(matrix)
    scores = clf.score_samples(matrix)   # higher = more normal
    preds = clf.predict(matrix)          # -1 = outlier, 1 = inlier

    candidates = [
        AnomalyCandidate(f.src_ip, round(float(-s), 4), bool(p == -1), f)
        for f, s, p in zip(feats, scores, preds)
    ]
    candidates.sort(key=lambda c: c.score, reverse=True)
    if top_k is not None:
        candidates = candidates[:top_k]
    return AnomalyResult(candidates, len(feats), False)
