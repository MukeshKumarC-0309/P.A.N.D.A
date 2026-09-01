"""
Console I/O for the PANDA CLI: the startup banner, command input, and the
help text for the security commands.
"""


def banner():
    print("-" * 60)
    print("P.A.N.D.A")
    print("Secure vault + threat detection platform")
    print("-" * 60)
    print("( Type HELP for commands and QUIT to exit )")


def help():
    print("-" * 60)
    print("COMMANDS")
    print("-" * 60)
    print(" VAULT    - Unlock the encrypted vault to view/edit your records")
    print(" TDR      - Scan the threat telemetry and store findings as cases")
    print("            (TDR FRESH rebuilds; TDR LIVE pulls from Splunk)")
    print(" CASES    - Browse the stored TDR cases, detections and reports")
    print(" SET      - Set the vault password (first-time setup)")
    print(" CHANGE   - Change the vault password (re-encrypts the vault)")
    print(" HELP     - Show this list")
    print(" QUIT     - Exit PANDA")
    print("-" * 60)


def takecommand():
    tc = input('YOU : ')
    return tc
