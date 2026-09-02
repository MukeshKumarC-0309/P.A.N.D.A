"""Generate a SYNTHETIC multi-source demo capture for the anomaly layer.

This is fabricated data (NOT a real capture). Its only purpose is to provide
enough distinct source IPs, with varied behavior, for the unsupervised anomaly
layer to model — so `tdr anomaly` demonstrates itself fully offline, without a
lab. Real evaluation still needs a real capture (see README / RESULTS).

Deterministic: same output every run. Regenerate with:
    python scripts/make_demo_fixture.py
"""
import json
import pathlib
from datetime import datetime, timedelta

BASE = datetime.fromisoformat("2026-08-20T09:00:00+00:00")
HOST = "WORKSTATION-01"


def t(sec):
    return (BASE + timedelta(seconds=sec)).isoformat()


def failed(ip, user, sec):
    return {"_time": t(sec), "Account_Name": ["-", user],
            "Source_Network_Address": ip, "host": HOST, "Logon_Type": "3"}


def success(ip, user, sec):
    return {"_time": t(sec), "Account_Name": ["-", user],
            "Source_Network_Address": ip, "host": HOST, "Logon_Type": "3"}


def created(creator, acct, sec):
    return {"_time": t(sec), "host": HOST, "Account_Name": [creator, acct]}


def cowrie(ip, sec, eventid="cowrie.login.failed", session="sess"):
    return {"_time": t(sec), "eventid": eventid, "session": session,
            "src_ip": ip, "username": "root", "message": None}


def build():
    failed_logins, successful_logons, account_creations, cowrie_events = [], [], [], []
    sec = 0

    # 9 benign baseline sources: light, ordinary activity (the "normal" the
    # anomaly layer measures deviation against).
    for i in range(1, 10):
        ip = "10.0.0.{}".format(i)
        for _ in range(1 + (i % 2)):                 # 1-2 failed attempts (below chain threshold)
            failed_logins.append(failed(ip, "jdoe" if i % 2 else "svc_backup", sec))
            sec += 37
        if i % 3 == 0:                               # some benign successes
            successful_logons.append(success(ip, "jdoe", sec))
            sec += 11

    # Loud brute-force outlier: one account hammered hard, also seen on the
    # honeypot (cross-surface presence).
    for _ in range(60):
        failed_logins.append(failed("10.0.0.50", "administrator", sec))
        sec += 9
    for _ in range(12):
        cowrie_events.append(cowrie("10.0.0.50", sec, session="brute"))
        sec += 5

    # Broad password-spray outlier: many accounts, one attempt each.
    for j in range(1, 16):
        failed_logins.append(failed("10.0.0.60", "user{:02d}".format(j), sec))
        sec += 13

    # A benign-looking account creation (bonus standalone case for `tdr`).
    account_creations.append(created("jdoe", "contractor_temp", sec))

    return {
        "_comment": ("SYNTHETIC demo data (fabricated, NOT a real capture). Provides "
                     "enough distinct sources for the anomaly layer to model offline. "
                     "Real evaluation needs a real capture."),
        "cowrie": cowrie_events,
        "failed_logins": failed_logins,
        "successful_logons": successful_logons,
        "account_creations": account_creations,
    }


def main():
    data = build()
    out = pathlib.Path(__file__).resolve().parent.parent / "test_data" / "demo_multi_source.json"
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    ips = {r["Source_Network_Address"] for r in data["failed_logins"]}
    print("wrote {} — {} failed logons, {} distinct source IPs".format(
        out, len(data["failed_logins"]), len(ips)))


if __name__ == "__main__":
    main()
