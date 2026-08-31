"""Synthetic severity benchmark — an honest ML methodology demonstration.

This is NOT the production scorer. Production severity is a deterministic,
auditable policy (see severity_model.py / the bridge); it is intentionally not a
learned model. This module is a separate experiment that shows the ML
*methodology* on a synthetic dataset: a generative process with realistic
feature correlations and injected label noise, a stratified train/test split,
and honest held-out metrics (accuracy, macro-F1, a confusion matrix, feature
importances, and the train-vs-test generalization gap).

Why synthetic, and why it is honest: there is no corpus of real, analyst-labeled
severity decisions to train on, so a model trained on the policy's own labels
would merely recover the rule (near-perfect by construction — meaningless). To
make it a genuine learning problem, the labels carry **noise** (modelling
analyst disagreement near boundaries), so perfect accuracy is impossible and the
held-out score actually measures generalization. The explicit claim is narrow:
this demonstrates sound ML methodology on synthetic data — it does NOT claim
real-world detection accuracy, which would require real labeled incidents.

Run:  python -m panda_tdr.severity_experiment
"""

import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

FEATURE_NAMES = [
    "confidence_tier",   # 0 low / 1 medium / 2 high
    "logon_type",        # 0 interactive / 1 network
    "command_danger",    # 0 not / 1 dangerous
    "attempt_volume",    # failed-attempt count
    "distinct_accounts", # breadth of targeting
    "dwell_seconds",     # first attempt -> outcome
    "off_hours",         # 0 business hours / 1 off hours
]
CLASSES = ["low", "medium", "high", "critical"]
_THRESHOLDS = [1.2, 2.5, 3.8]  # digitize a continuous risk score into 4 classes


def _risk_score(X):
    """Continuous risk from the features (the signal the labels encode).

    A multi-feature policy with an interaction term (a dangerous command from a
    high-confidence correlation is decisively worse), so the decision boundary
    is not a single threshold — a shallow tree must actually partition the space.
    """
    tier, logon, danger = X[:, 0], X[:, 1], X[:, 2]
    volume, accounts, _dwell, off = X[:, 3], X[:, 4], X[:, 5], X[:, 6]
    return (
        tier
        + 1.5 * danger
        + 1.2 * (volume >= 20)
        + 0.6 * (accounts >= 8)
        + 0.4 * off
        + 0.3 * logon
        + 1.0 * ((danger == 1) & (tier == 2))   # interaction
    )


def _bucket(score):
    return np.array(CLASSES)[np.digitize(score, _THRESHOLDS)]


def policy_labels(X):
    """The noiseless label for each row — what the policy alone would assign."""
    return _bucket(_risk_score(X))


def build_dataset(n=1500, seed=0, noise=0.6):
    """Generate (X, y, feature_names): synthetic features + noisy severity labels.

    Features are sampled with realistic distributions and correlations (dangerous
    commands are likelier at high volume). Labels come from the risk policy plus
    Gaussian noise on the score before bucketing — so boundary cases are
    ambiguous and perfect accuracy is impossible. Features are identical for a
    given seed regardless of `noise` (features are drawn before the noise), so
    noise=0 recovers the pure policy labels.
    """
    rng = np.random.RandomState(seed)
    tier = rng.choice([0, 1, 2], size=n, p=[0.4, 0.4, 0.2])
    logon = rng.choice([0, 1], size=n, p=[0.3, 0.7])
    volume = np.clip(1 + rng.poisson(15, size=n), 1, 100)
    accounts = np.clip(1 + rng.poisson(4, size=n), 1, 40)
    p_danger = 0.15 + 0.25 * (volume >= 20)
    danger = (rng.random(n) < p_danger).astype(int)
    dwell = np.clip(rng.exponential(600, size=n), 5, 3600)
    off = rng.choice([0, 1], size=n, p=[0.6, 0.4])

    X = np.column_stack([tier, logon, danger, volume, accounts, dwell, off]).astype(float)
    score = _risk_score(X)
    if noise:
        score = score + rng.normal(0.0, noise, size=n)
    return X, _bucket(score), list(FEATURE_NAMES)


def run_experiment(n=1500, seed=0, noise=0.6, test_size=0.3, max_depth=5):
    """Train on a split, evaluate on the held-out set, return honest metrics."""
    X, y, names = build_dataset(n=n, seed=seed, noise=noise)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y)

    clf = DecisionTreeClassifier(
        max_depth=max_depth, class_weight="balanced", random_state=seed).fit(X_tr, y_tr)
    pred = clf.predict(X_te)

    train_acc = accuracy_score(y_tr, clf.predict(X_tr))
    test_acc = accuracy_score(y_te, pred)
    baseline = DummyClassifier(strategy="most_frequent").fit(X_tr, y_tr)
    base_acc = accuracy_score(y_te, baseline.predict(X_te))

    return {
        "n": n, "noise": noise, "max_depth": max_depth, "test_size": test_size,
        "train_accuracy": train_acc,
        "test_accuracy": test_acc,
        "generalization_gap": train_acc - test_acc,
        "baseline_accuracy": base_acc,
        "macro_f1": f1_score(y_te, pred, average="macro", labels=CLASSES),
        "confusion_matrix": confusion_matrix(y_te, pred, labels=CLASSES),
        "feature_importances": dict(zip(names, clf.feature_importances_)),
        "classes": list(CLASSES),
        "test_size_rows": len(y_te),
    }


def render_report(m):
    """Render the metrics as a plain-text report (no plotting dependency)."""
    lines = [
        "=" * 66,
        "Synthetic severity benchmark — ML methodology demo (NOT production)",
        "=" * 66,
        f" dataset        : {m['n']} synthetic rows, label noise sigma={m['noise']}",
        f" model          : DecisionTree(max_depth={m['max_depth']}, class_weight=balanced)",
        f" split          : {int((1 - m['test_size']) * 100)}/{int(m['test_size'] * 100)} stratified train/test",
        "",
        f" train accuracy : {m['train_accuracy']:.3f}",
        f" TEST accuracy  : {m['test_accuracy']:.3f}   (held-out — the honest number)",
        f" baseline (majority): {m['baseline_accuracy']:.3f}",
        f" generalization gap : {m['generalization_gap']:.3f}   (train - test)",
        f" macro-F1 (test): {m['macro_f1']:.3f}",
        "",
        " Confusion matrix (rows = actual, cols = predicted):",
        "            " + "".join(f"{c:>9}" for c in m["classes"]),
    ]
    for label, row in zip(m["classes"], m["confusion_matrix"]):
        lines.append(f"   {label:>8} " + "".join(f"{v:>9d}" for v in row))
    lines += ["", " Feature importances:"]
    for name, imp in sorted(m["feature_importances"].items(), key=lambda kv: -kv[1]):
        lines.append(f"   {name:<18} {imp:.3f}")
    lines += [
        "",
        " Honest scope: synthetic data with injected label noise. This shows the",
        " methodology (train/test discipline, class imbalance, interpretability),",
        " NOT real-world detection accuracy. Production severity is a separate,",
        " deterministic policy — see severity_model.py.",
        "=" * 66,
    ]
    return "\n".join(lines)


def main():
    print(render_report(run_experiment()))


if __name__ == "__main__":
    main()
