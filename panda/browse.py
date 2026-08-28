"""Interactive browse view for the TDR case store.

The presentation half of panda/cases.py (which is pure data access, no I/O).
Lists stored cases, filters by severity, and opens a case's detections and
incident reports. Used from two places that share this one implementation: the
top-level `cases` command (panda/main.py) and the in-vault CASES menu entry
(panda/vault.py). Both call it only inside an unlocked vault session, so
evidence is readable by construction only after login.
"""
from tabulate import tabulate

from panda import cases


def browse_cases():
    """List cases (optionally filtered by severity), then drill into one."""
    sev = input("Filter by severity? ( low | medium | high | critical, blank = all ) : ").strip()
    header = ["Case ID", "Created", "Title", "Severity", "Confidence", "Status", "Source IP", "Summary"]
    print(tabulate(cases.list_cases(sev or None), headers=header, tablefmt="grid"))
    pick = input("Enter a Case ID to open ( blank to go back ) : ").strip()
    if not pick.isdigit():
        print()
        return
    cid = int(pick)
    case = cases.get_case(cid)
    if case is None:
        print("P.A.N.D.A : No such case.")
        print()
        return
    det_header = ["Detection ID", "Case ID", "Detected", "Rule", "Source",
                  "Severity", "Confidence", "Source IP", "Username", "Evidence"]
    print("\nDetections:")
    print(tabulate(cases.get_detections(cid), headers=det_header, tablefmt="grid"))

    # Other cases keyed on the same source IP — the same actor seen through a
    # different lens (e.g. a Windows kill chain and a cross-source correlation).
    # Kept as separate cases by design; this is how an analyst connects them.
    source_ip = case[6]
    related = cases.related_by_source_ip(source_ip, exclude_case_id=cid)
    if related:
        print("\nRelated cases (same source IP {}):".format(source_ip))
        print(tabulate([(r[0], r[2], r[3]) for r in related],
                       headers=["Case ID", "Title", "Severity"], tablefmt="grid"))
    reps = cases.get_reports(cid)
    print("\nReports:")
    print(tabulate([(r[0], r[2], r[3]) for r in reps],
                   headers=["Report ID", "Audience", "Created"], tablefmt="grid"))
    rpick = input("Enter a Report ID to open ( blank to skip ) : ").strip()
    if rpick.isdigit():
        report = cases.get_report(int(rpick))
        if report is None:
            print("P.A.N.D.A : No such report.")
        else:
            print("-" * 100)
            print("Incident report (", report[2], ") - case", report[1])
            print("-" * 100)
            print(report[4])  # body
            print("-" * 100)
    print()
