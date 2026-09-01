"""Bridge tests (panda.bridge over the offline snapshot).

Verify that a TDR scan persists the snapshot's findings into the case store
with the right shape: one case per incident, a detection per chain stage, two
reports per chain, and — the honest bit — that a finding a chain already
subsumes is skipped, while one it does NOT cover stays a standalone case.

The snapshot's shape is instructive: source 10.0.2.3 both cracked the
'eviluser' account (a full kill chain) AND separately hammered 'bmleg' without
ever succeeding. The chain covers (10.0.2.3, eviluser); the bmleg brute-force
is a different account with no success, so it correctly stays standalone. Only
the 'backdoor' creation, attached to the chain as its persistence stage, is
subsumed. The `db` fixture wipes cases/detections/reports around each test.
"""
from panda import bridge, cases
from panda_tdr.snapshot import load_snapshot


def test_default_source_is_snapshot(db):
    s = bridge.scan_and_persist()
    assert s["source"] == "snapshot"


def test_fresh_rebuilds_instead_of_appending(db):
    first = bridge.scan_and_persist()
    assert len(cases.list_cases()) == first["cases"]
    # Default appends: a second run doubles the store.
    bridge.scan_and_persist()
    assert len(cases.list_cases()) == first["cases"] * 2
    # fresh clears first, so the store matches a single run again.
    third = bridge.scan_and_persist(fresh=True)
    assert third["fresh"] is True
    assert len(cases.list_cases()) == first["cases"]


def test_live_requested_but_unavailable_falls_back(db, monkeypatch):
    # No SDK / no creds -> live degrades to the snapshot, same findings, no crash.
    monkeypatch.setattr(bridge.live_source, "live_available", lambda: False)
    s = bridge.scan_and_persist(live=True)
    assert "unavailable" in s["source"]
    assert s["cases"] == 6            # identical to a snapshot run


def test_live_uses_injected_loader(db, monkeypatch):
    # Simulate the [live] extra being available: the bridge must call load_live
    # and persist its data. Feed it the snapshot data so counts are comparable.
    monkeypatch.setattr(bridge.live_source, "live_available", lambda: True)
    monkeypatch.setattr(bridge.live_source, "load_live", lambda **kw: load_snapshot())
    s = bridge.scan_and_persist(live=True)
    assert s["source"] == "live (Splunk)"
    assert s["cases"] == 6 and s["correlations"] == 1


def test_scan_persists_expected_shape(db):
    s = bridge.scan_and_persist()

    # One confirmed kill chain (10.0.2.3 -> eviluser -> backdoor).
    assert s["chains"] == 1
    # The bmleg brute-force is a different account with no success -> NOT
    # subsumed, stays standalone.
    assert s["skipped_brute_spray"] == 0
    assert s["brute_spray"] == 1
    # The chain absorbs the 'backdoor' creation; the other three creations have
    # no preceding breach and stay standalone.
    assert s["skipped_account_creations"] == 1
    assert s["account_creations"] == 3
    # One cross-source correlation (10.0.2.3 on honeypot + Windows), NOT deduped
    # against the chain — a different sensor / different claim.
    assert s["correlations"] == 1

    # Totals: 1 chain + 1 brute-force + 3 account-creation + 1 correlation = 6.
    assert s["cases"] == 6
    # 3 chain-stage + 1 brute-force + 3 account-creation + 1 correlation = 8.
    assert s["detections"] == 8
    # Reports: chain (technical + plain) + correlation (technical) = 3.
    assert s["reports"] == 3


def _correlation_report_body(case_list):
    corr = [c for c in case_list if "correlation" in c[2].lower()][0]
    reps = cases.get_reports(corr[0])
    return reps[0][4]  # body is the last column


def test_default_run_is_deterministic_no_ai(db):
    # No crewai / no key in the test env -> the default provider is None, so the
    # run is fully deterministic and the correlation report is the raw card.
    s = bridge.scan_and_persist()
    assert s["ai_polish"] is False
    assert s["polished"] == 0 and s["polish_fallbacks"] == 0
    assert "Cross-source correlation" in _correlation_report_body(cases.list_cases())


def test_clean_polish_is_stored(db):
    # A polisher that preserves severity + IPs passes the guard -> polished body.
    polisher = lambda card: "POLISHED >>\n" + card
    s = bridge.scan_and_persist(card_polisher=polisher)
    assert s["ai_polish"] is True
    assert s["polished"] == 1 and s["polish_fallbacks"] == 0
    assert _correlation_report_body(cases.list_cases()).startswith("POLISHED >>")


def test_drifting_polish_falls_back_to_card(db):
    # Drops the source IP -> guard rejects -> deterministic card ships.
    polisher = lambda card: "A medium-severity cross-source correlation, no addresses."
    s = bridge.scan_and_persist(card_polisher=polisher)
    assert s["polished"] == 0 and s["polish_fallbacks"] == 1
    assert "10.0.2.3" in _correlation_report_body(cases.list_cases())


def test_raising_polish_falls_back_to_card(db):
    def boom(_card):
        raise RuntimeError("API down")
    s = bridge.scan_and_persist(card_polisher=boom)
    assert s["polish_fallbacks"] == 1
    assert "Cross-source correlation" in _correlation_report_body(cases.list_cases())


def _chain_technical_body(case_list):
    chain = [c for c in case_list if c[2].startswith("Multi-stage")][0]
    tech = [r for r in cases.get_reports(chain[0]) if r[2] == "technical"][0]
    return tech[4]


def test_section_polish_applied_to_chain_report(db):
    # A clean section polisher preserves facts -> both prose sections kept, and
    # the stored technical report shows the polish; the plain report is untouched.
    s = bridge.scan_and_persist(section_polisher=lambda sec: "POLISHED " + sec)
    assert s["ai_polish"] is True
    assert s["polished"] == 2 and s["polish_fallbacks"] == 0
    assert "POLISHED " in _chain_technical_body(cases.list_cases())


def test_section_polish_reverts_on_raise(db):
    def boom(_sec):
        raise RuntimeError("API down")
    s = bridge.scan_and_persist(section_polisher=boom)
    assert s["polished"] == 0 and s["polish_fallbacks"] == 2
    # Deterministic technical report still persisted, facts intact.
    body = _chain_technical_body(cases.list_cases())
    assert "MITRE" in body and "10.0.2.3" in body


def test_correlation_case_is_persisted_and_linked_by_ip(db):
    bridge.scan_and_persist()
    corr = [c for c in cases.list_cases() if "correlation" in c[2].lower()]
    assert len(corr) == 1
    case = corr[0]
    # Cross-source correlation on the snapshot: tier high, severity medium.
    assert case[3] == "medium"        # severity
    assert case[4] == "high"          # confidence (correlation tier)
    assert case[6] == "10.0.2.3"      # source_ip — the link to the chain case
    # One correlation detection + one technical report.
    dets = cases.get_detections(case[0])
    assert len(dets) == 1 and dets[0][3] == "correlation"    # rule
    reps = cases.get_reports(case[0])
    assert [r[2] for r in reps] == ["technical"]
    # The chain case shares that source_ip — the intended analyst link.
    chain = [c for c in cases.list_cases() if c[2].startswith("Multi-stage")][0]
    assert chain[6] == "10.0.2.3"


def test_persisted_rows_match_summary(db):
    s = bridge.scan_and_persist()
    assert len(cases.list_cases()) == s["cases"]

    # Find the chain case and check its shape: 3 stage detections, 2 reports.
    chain_cases = [c for c in cases.list_cases() if c[2].startswith("Multi-stage")]
    assert len(chain_cases) == 1
    chain_id = chain_cases[0][0]
    assert len(cases.get_detections(chain_id)) == 3            # 3 stages
    audiences = {r[2] for r in cases.get_reports(chain_id)}
    assert audiences == {"technical", "plain"}


def test_subsumed_creation_is_not_a_standalone_case(db):
    bridge.scan_and_persist()
    titles = [c[2] for c in cases.list_cases()]
    # 'backdoor' was attached to the chain as persistence -> no standalone case.
    assert not any("backdoor" in t for t in titles)
    # A non-subsumed account creation still stands alone...
    assert any("evilusessr" in t for t in titles)
    # ...and the separate, never-successful brute-force is its own case.
    assert any(t.startswith("Brute-force") for t in titles)
