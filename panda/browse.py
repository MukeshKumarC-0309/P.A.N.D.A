"""Interactive browse view for the TDR case store, rendered with rich.

The presentation half of panda/cases.py (which is pure data access, no I/O).
Lists cases, opens one to show its full detail + detections + related cases +
reports, renders incident reports as formatted Markdown, and records an analyst
verdict. Shared by the top-level `cases` command and the in-vault CASES menu;
both call it only inside an unlocked vault session.

Data cells are escaped (rich.markup.escape) so a bracket in a title or summary
is never mistaken for markup; severity/disposition come from ui as controlled
markup. rich wraps every column to the console width, so nothing overflows.
"""
from rich import box
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from panda import cases, ui


def browse_cases():
    """List cases (optionally filtered by severity), then drill into one."""
    sev = input("Filter by severity? ( low | medium | high | critical, blank = all ) : ").strip()
    rows = cases.list_cases(sev or None)
    if not rows:
        ui.console.print("[muted]No cases yet — run [bold]TDR[/bold] to scan the telemetry.[/muted]")
        return
    ui.console.print(_list_table(rows))
    pick = input("Enter a Case ID to open ( blank to go back ) : ").strip()
    if not pick.isdigit():
        return
    case = cases.get_case(int(pick))
    if case is None:
        ui.err("No such case.")
        return
    _open_case(case)


def _list_table(rows):
    t = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", expand=False)
    for col, kw in (("ID", {"justify": "right"}), ("Severity", {}), ("Confidence", {}),
                    ("Source IP", {}), ("Title", {}), ("Verdict", {})):
        t.add_column(col, **kw)
    for r in rows:
        # cases columns: id, created, title, severity, confidence, status,
        # source_ip, summary, disposition, [fingerprint]
        t.add_row(str(r[0]), ui.severity(r[3]), escape(r[4] or ""),
                  escape(r[6] or ""), escape(r[2] or ""),
                  ui.disposition(r[8] if len(r) > 8 else None))
    return t


def _open_case(case):
    cid = case[0]
    meta = Table(box=None, show_header=False)
    meta.add_column(style="muted", justify="right")
    meta.add_column()
    meta.add_row("Created", escape(case[1] or ""))
    meta.add_row("Severity", ui.severity(case[3]))
    meta.add_row("Confidence", escape(case[4] or ""))
    meta.add_row("Status", escape(case[5] or ""))
    meta.add_row("Source IP", escape(case[6] or ""))
    meta.add_row("Verdict", ui.disposition(case[8]))
    meta.add_row("Summary", escape(case[7] or ""))
    ui.console.print(Panel(
        meta, title="[title]Case {} — {}[/title]".format(cid, escape(case[2] or "")),
        border_style="cyan", expand=False))

    _detections(cid)
    _related(case, cid)
    _reports(cid)
    _prompt_disposition(cid)


def _detections(cid):
    dets = cases.get_detections(cid)
    ui.console.print("[bold]Detections[/bold]")
    if not dets:
        ui.console.print("[muted]  none[/muted]")
        return
    t = Table(box=box.SIMPLE, header_style="bold")
    for col in ("Rule", "Source", "Severity", "Source IP", "Username", "Evidence"):
        t.add_column(col)
    for d in dets:
        # detections columns: id, case_id, detected_at, rule, source, severity,
        # confidence, source_ip, username, evidence
        t.add_row(escape(d[3] or ""), escape(d[4] or ""), ui.severity(d[5]),
                  escape(d[7] or ""), escape(d[8] or ""), escape(d[9] or ""))
    ui.console.print(t)


def _related(case, cid):
    related = cases.related_by_source_ip(case[6], exclude_case_id=cid)
    if not related:
        return
    ui.console.print("[bold]Related cases (same source IP {})[/bold]".format(escape(case[6] or "")))
    t = Table(box=box.SIMPLE, header_style="bold")
    t.add_column("ID", justify="right")
    t.add_column("Title")
    t.add_column("Severity")
    for r in related:
        t.add_row(str(r[0]), escape(r[2] or ""), ui.severity(r[3]))
    ui.console.print(t)


def _reports(cid):
    reps = cases.get_reports(cid)
    if not reps:
        return
    t = Table(box=box.SIMPLE, header_style="bold")
    t.add_column("Report ID", justify="right")
    t.add_column("Audience")
    t.add_column("Created")
    for r in reps:
        t.add_row(str(r[0]), escape(r[2] or ""), escape(r[3] or ""))
    ui.console.print("[bold]Reports[/bold]")
    ui.console.print(t)
    rpick = input("Enter a Report ID to open ( blank to skip ) : ").strip()
    if not rpick.isdigit():
        return
    report = cases.get_report(int(rpick))
    if report is None:
        ui.err("No such report.")
        return
    # Render the report body as formatted Markdown (headings, tables, lists).
    ui.console.rule("[title]Incident report ({}) — case {}[/title]".format(report[2], report[1]))
    ui.console.print(Markdown(report[4]))
    ui.console.rule()


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
        ui.warn("Unknown verdict — leaving the case unmarked.")
    else:
        ui.ok("Recorded verdict '{}' on case {}.".format(verdict, case_id))
