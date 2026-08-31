"""Tests for the synthetic severity benchmark (the ML methodology demo).

These assert the properties that make it an *honest* ML exercise rather than a
policy in disguise: the labels carry real noise (so perfect accuracy is
impossible), the train/test evaluation generalizes (beats a majority baseline
without a large train-test gap), and the run is reproducible. Bounds are loose
so they survive minor scikit-learn version differences.
"""
from panda_tdr.severity_experiment import (
    CLASSES,
    FEATURE_NAMES,
    build_dataset,
    policy_labels,
    render_report,
    run_experiment,
)


def test_dataset_shape_and_classes():
    X, y, names = build_dataset(n=1500, seed=0)
    assert X.shape == (1500, 7)
    assert names == FEATURE_NAMES
    assert set(y) <= set(CLASSES)
    assert len(set(y)) >= 3            # a real multi-class problem, not degenerate


def test_noise_is_real_and_features_are_stable():
    # noise=0 recovers the pure policy; noise>0 flips a meaningful share of labels.
    Xc, yc, _ = build_dataset(seed=0, noise=0)
    Xn, yn, _ = build_dataset(seed=0, noise=0.6)
    assert (yc == policy_labels(Xc)).all()
    flipped = (yn != policy_labels(Xn)).sum()
    assert flipped > 0.1 * len(yn)     # non-trivial ambiguity near boundaries
    assert (Xc == Xn).all()            # features independent of the noise level


def test_experiment_generalizes_and_is_honest():
    m = run_experiment(seed=0)
    # Learns real signal: clearly beats the majority-class baseline...
    assert m["test_accuracy"] > m["baseline_accuracy"] + 0.1
    # ...but noise makes perfection impossible (not a policy-recovering 1.0)...
    assert 0.5 < m["test_accuracy"] < 0.95
    # ...and it generalizes: small, non-negative train-test gap.
    assert 0.0 <= m["generalization_gap"] < 0.25
    # Confusion matrix accounts for every held-out row.
    assert m["confusion_matrix"].sum() == m["test_size_rows"]
    # Importances form a distribution.
    assert abs(sum(m["feature_importances"].values()) - 1.0) < 1e-6


def test_experiment_is_reproducible():
    assert run_experiment(seed=0)["test_accuracy"] == run_experiment(seed=0)["test_accuracy"]


def test_report_states_its_honest_scope():
    report = render_report(run_experiment(seed=0))
    assert "NOT production" in report
    assert "synthetic" in report.lower()
