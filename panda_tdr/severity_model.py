"""Severity decision tree for correlated pairs (Phase 1.5 Step 6).

Deliberately SHALLOW (max_depth=3): very few real examples exist, and a shallow
tree gives stable, honestly-interpretable splits — see the max_depth reasoning in
the design notes. It maps a correlated pair's features to a severity label.

HONESTY CAVEAT (state this wherever metrics are reported): the training data is a
small POLICY-DERIVED set (8 synthetic + 1 real pair), so the tree RECOVERS the
severity policy rather than discovering it. Near-perfect recall/F1 is BY
CONSTRUCTION — a methodology demonstration and a source of readable rule paths,
NOT evidence of generalization to unseen attacks. That waits for real labeled
data to accumulate.

BOUNDARY CONDITION (Type 10 / RDP): logon_type is framed as network(3) vs
interactive(2), per the correlation-agent contract. This lab has ZERO Type 10
(RDP / "RemoteInteractive") events — which are interactive AND carry a source IP.
The dataset therefore assumes interactive logons can only reach LOW confidence
(username-fallback), never an IP-match tier. If Type 10 data ever appears, that
assumption breaks and logon_type needs a third category.

logon_type LOAD-BEARING NOTE: under the current labels, severity is a function of
command_danger + confidence_tier ONLY. interactive is confined to LOW tier, and
severity there depends only on command_danger, so logon_type never flips a label.
It is kept as a documented (currently-inert) input for when RDP data exists. Use
`used_features()` to see what the fitted tree actually branches on — any
description of the rule path MUST reflect that logon_type isn't load-bearing if
the tree doesn't split on it.
"""

from sklearn.tree import DecisionTreeClassifier, export_text

FEATURES = ["confidence_tier", "logon_type", "command_danger"]

# Ordinal / binary encodings, chosen so the tree's threshold splits read cleanly.
_TIER = {"low": 0, "medium": 1, "high": 2}
_LOGON = {"interactive": 0, "network": 1}
_DANGER = {"not": 0, "dangerous": 1}

# (confidence_tier, logon_type, command_danger, severity, source)
# Policy: command_danger=dangerous -> high (UNCAPPED by confidence tier);
# else tier=high (=> network) -> medium; else -> low.
# interactive only appears at LOW tier (it can't IP-match — no real source IP).
LABELED_DATA = [
    ("high",   "network",     "dangerous", "high",   "synthetic"),
    ("high",   "network",     "not",       "medium", "synthetic"),
    ("medium", "network",     "dangerous", "high",   "synthetic"),
    ("medium", "network",     "not",       "low",    "synthetic"),
    ("low",    "network",     "dangerous", "high",   "synthetic"),
    ("low",    "network",     "not",       "low",    "synthetic"),
    ("low",    "interactive", "dangerous", "high",   "synthetic"),
    ("low",    "interactive", "not",       "low",    "synthetic"),
    ("high",   "network",     "not",       "medium", "real-2026-08-04"),  # the real 12:24 pair
]


def _encode_row(tier, logon, danger):
    return [_TIER[tier], _LOGON[logon], _DANGER[danger]]


def build_dataset():
    """Return (X, y) — encoded feature rows and severity labels."""
    X = [_encode_row(t, l, d) for (t, l, d, _y, _s) in LABELED_DATA]
    y = [row[3] for row in LABELED_DATA]
    return X, y


def train_severity_tree(max_depth=3):
    """Fit the shallow severity tree. class_weight='balanced' guards the class
    imbalance (an accuracy-trap lesson from the earlier ML methodology pass)."""
    X, y = build_dataset()
    clf = DecisionTreeClassifier(
        max_depth=max_depth, class_weight="balanced", random_state=0
    )
    clf.fit(X, y)
    return clf


def used_features(clf):
    """Names of the features the fitted tree actually branches on (feature
    index -2 marks a leaf)."""
    return sorted({FEATURES[i] for i in clf.tree_.feature if i >= 0})


def rule_path_text(clf):
    """Human-readable rule path for the Reporter agent / documentation."""
    return export_text(clf, feature_names=FEATURES)
