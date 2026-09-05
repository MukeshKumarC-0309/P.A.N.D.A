"""Interactive browse view for the TDR case store.

The presentation half of panda/cases.py (which is pure data access, no I/O).
Lists stored cases, filters by severity, and opens a case's detections and
incident reports. Used from two places that share this one implementation: the
top-level `cases` command (panda/main.py) and the in-vault CASES menu entry
(panda/vault.py). Both call it only inside an unlocked vault session, so
evidence is readable by construction only after login.
"""
from tabulate import tabulate

from panda import cases, system

# Cap the free-text columns so long titles/summaries/evidence wrap instead of
# blowing a case table past the terminal width. None = no cap; ints wrap. Lengths
# are per-column, matching each table's header order.
_CASES_WIDTHS = [None, None, 34, None, None, None, None, 44, None]  # Title, Summary
_DET_WIDTHS = [None] * 9 + [50]                                     # Evidence
_RELATED_WIDTHS = [None, 44, None]                                  # Title


def _grid(rows, headers, widths, colorizers=None):
    """tabulate a grid, wrapping wide columns — but only when there are rows.

    tabulate raises on an empty row list when maxcolwidths is set, so an empty
    table (no cases, or a case with no detections) omits the wrapping and just
    renders the header. Keeps the browse view from crashing on an empty vault.
    `colorizers`, when given, maps a column index to a styling function (e.g.
    severity/disposition color); tabulate strips ANSI for width, so alignment is
    unaffected.
    """
    if not rows:
        return tabulate(rows, headers=headers, tablefmt="grid")
    clean = []
    for row in rows:
        # None cells break tabulate's wrapper -> render as empty strings.
        cells = ["" if c is None else c for c in row]
        for idx, fn in (colorizers or {}).items():
            cells[idx] = fn(cells[idx])
        clean.append(cells)
    return tabulate(clean, headers=headers, tablefmt="grid", maxcolwidths=widths)


def browse_cases():
    """List cases (optionally filtered by severity), then drill into one."""
    sev = input("Filter by severity? ( low | medium | high | critical, blank = all ) : ").strip()
    header = ["Case ID", "Created", "Title", "Severity", "Confidence", "Status",
              "Source IP", "Summary", "Disposition"]
    print(_grid(cases.list_cases(sev or None), header, _CASES_WIDTHS,
                colorizers={3: system.severity, 8: system.disposition}))
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
    print(system.style("\nDetections:", system.BOLD))
    print(_grid(cases.get_detections(cid), det_header, _DET_WIDTHS,
                colorizers={5: system.severity}))

    # Other cases keyed on the same source IP — the same actor seen through a
    # different lens (e.g. a Windows kill chain and a cross-source correlation).
    # Kept as separate cases by design; this is how an analyst connects them.
    source_ip = case[6]
    related = cases.related_by_source_ip(source_ip, exclude_case_id=cid)
    if related:
        print(system.style("\nRelated cases (same source IP {}):".format(source_ip), system.BOLD))
        print(_grid([(r[0], r[2], r[3]) for r in related],
                    ["Case ID", "Title", "Severity"], _RELATED_WIDTHS,
                    colorizers={2: system.severity}))
    reps = cases.get_reports(cid)
    print(system.style("\nReports:", system.BOLD))
    print(tabulate([(r[0], r[2], r[3]) for r in reps],
                   headers=["Report ID", "Audience", "Created"], tablefmt="grid"))
    rpick = input("Enter a Report ID to open ( blank to skip ) : ").strip()
    if rpick.isdigit():
        report = cases.get_report(int(rpick))
        if report is None:
            print("P.A.N.D.A : No such report.")
        else:
            rule = system.style("-" * 100, system.DIM)
            print(rule)
            print(system.style("Incident report ({}) - case {}".format(report[2], report[1]),
                               system.BOLD, system.BRIGHT_CYAN))
            print(rule)
            print(report[4])  # body
            print(rule)
    _prompt_disposition(cid)
    print()


def _prompt_disposition(case_id):
    """Offer to record an analyst verdict on the open case (the ground-truth
    capture that a future learning loop would train on). Blank = leave as-is."""
    verdict = input(
        "Mark this case ( confirmed | false_positive | benign, blank = skip ) : ").strip()
    if not verdict:
        return
    try:
        cases.set_disposition(case_id, verdict)
    except ValueError:
        print("P.A.N.D.A : Unknown verdict — leaving the case unmarked.")
    else:
        print("P.A.N.D.A : Recorded verdict '{}' on case {}.".format(
            system.disposition(verdict), case_id))
