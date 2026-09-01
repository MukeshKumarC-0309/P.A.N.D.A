"""Tests for the unsupervised anomaly layer.

Exercise the feature engineering (per-source aggregation, loopback exclusion),
the honest thin-data guard, and that a clearly-deviant source ranks top. No
labels, no network — IsolationForest over fabricated records.
"""
from types import SimpleNamespace

from panda_tdr.windows_records import WindowsRecord
from panda_tdr import anomaly


def w(ip, user, ts, event_id="4625", host="HOST1"):
    return WindowsRecord(timestamp=ts, event_id=event_id, src_ip=ip,
                         username=user, host=host, logon_type="3")


def cow(ip, ts, eventid="cowrie.login.failed", message=None):
    return SimpleNamespace(src_ip=ip, timestamp=ts, eventid=eventid, message=message)


T = "2026-01-01T00:00:{:02d}+00:00".format


def test_features_aggregate_per_source_and_skip_loopback():
    failed = [w("10.0.0.1", "admin", T(0)), w("10.0.0.1", "admin", T(30)),
              w("10.0.0.1", "bob", T(45)), w("::1", "x", T(0))]
    feats = {f.src_ip: f for f in anomaly.extract_features(failed, [], [])}
    assert "::1" not in feats                      # loopback excluded
    f = feats["10.0.0.1"]
    assert f.failed_attempts == 3
    assert f.distinct_accounts == 2
    assert f.max_single_account == 2               # admin hit twice
    assert f.attempts_per_min > 0


def test_cowrie_commands_counted():
    cowrie = [cow("10.0.0.5", T(0)),
              cow("10.0.0.5", T(1), eventid="cowrie.command.input", message="CMD: whoami")]
    f = {x.src_ip: x for x in anomaly.extract_features([], [], cowrie)}["10.0.0.5"]
    assert f.cowrie_events == 2 and f.cowrie_commands == 1


def test_insufficient_data_is_reported_not_faked():
    # Two sources is far below the floor -> honest "insufficient", no candidates.
    failed = [w("10.0.0.1", "a", T(0)), w("10.0.0.2", "b", T(0))]
    res = anomaly.rank({"failed": failed, "success": [], "cowrie": []})
    assert res.insufficient is True and res.candidates == [] and res.n_sources == 2


def test_deviant_source_ranks_most_anomalous():
    # 9 quiet sources (a few failed logons each) + 1 loud one (sustained, broad).
    failed = []
    for i in range(9):
        ip = "10.0.1.{}".format(i)
        failed += [w(ip, "user", T(i)), w(ip, "user", T(i + 1))]
    loud = "10.0.9.9"
    failed += [w(loud, "acct{}".format(k), T(k % 60)) for k in range(80)]

    res = anomaly.rank({"failed": failed, "success": [], "cowrie": []})
    assert res.insufficient is False
    assert res.candidates[0].src_ip == loud        # the outlier ranks first
    assert res.candidates[0].is_outlier is True


def test_rank_is_deterministic_and_respects_top_k():
    failed = []
    for i in range(12):
        ip = "10.0.2.{}".format(i)
        failed += [w(ip, "user", T(i)) for _ in range(i + 1)]  # varying volume
    a = anomaly.rank({"failed": failed, "success": [], "cowrie": []}, top_k=3)
    b = anomaly.rank({"failed": failed, "success": [], "cowrie": []}, top_k=3)
    assert [c.src_ip for c in a.candidates] == [c.src_ip for c in b.candidates]
    assert len(a.candidates) == 3
