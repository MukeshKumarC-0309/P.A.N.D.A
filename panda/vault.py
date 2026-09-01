"""
PandaVault: the interactive record-management shell.

A small class (`VaultShell`) with one method per menu command, over the shared
encrypted connection. `DATABASE()` is kept as the public entry point (it builds
a shell and runs it) so callers don't change.

PANDA is security-only: the one built-in domain is the TDR evidence store
(browsed via CASES, which shares panda/browse.py with the top-level `cases`
command). Users can still define and query their own tables at runtime through
CREATOR mode — all of it goes through the validated DAO, never raw SQL on user
input. The database is embedded SQLite (stdlib sqlite3): a single local file per
device (config.DB_PATH), created empty on first run from schema.sql — a
zero-install, offline, per-user tool.
"""
import sqlite3

from tabulate import tabulate

from panda.db import connection as conobj, cursor as cur
from panda.db import safe_identifier, insert
from panda.browse import browse_cases


class VaultShell:
    """The interactive vault menu: browse TDR cases, and create/search your own
    tables. All table/column names are whitelist-validated and all values are
    bound as parameters, so no user input is ever interpolated into SQL."""

    def __init__(self):
        self.conn = conobj
        self.cur = cur

    # --- shared helpers ----------------------------------------------------

    @staticmethod
    def _error():
        print("P.A.N.D.A : An unexpected error has occured")
        print("P.A.N.D.A : Please check the values again")

    @staticmethod
    def _bad_identifier(what):
        print("P.A.N.D.A : Invalid {}.".format(what))
        print("P.A.N.D.A : Use letters, digits and underscores only.")

    # --- commands ----------------------------------------------------------

    def cases(self):
        # TDR evidence store: browse stored cases, filter by severity, and open
        # a case's detections and reports. One implementation, shared with the
        # top-level `cases` command (see panda/browse.py).
        browse_cases()

    def show_tables(self):
        self.cur.execute(
            "select name from sqlite_master where type='table' order by name")
        rows = self.cur.fetchall()
        self.conn.commit()
        print(tabulate(rows, headers=["Tables"], tablefmt="grid"))
        print()

    def help(self):
        print("-" * 100)
        print("Welcome to the Panda Vault. Listed below are commands that will help you  navigate through the Vault.")
        print()
        print("CASES : Browse the TDR evidence store - stored detections and incident reports, filterable by severity")
        print("\nBelow listed are commands that will help you access the features of P.A.N.D.A databases")
        print("\nSHOW TABLES:This command allows you to see what tables you have created so far")
        print("CREATOR MODE:This command allows you to create your own tables and maintain your own record")
        print("-" * 100)

    def create_table(self):
        table = self._prompt_identifier("Enter table name : ", "table name")
        if table is None:
            return
        # Identifiers can't be bound as parameters, so they're whitelist-validated
        # before interpolating — no raw user input reaches the DDL.
        self.cur.execute("create table if not exists {}(Serial_No TEXT)".format(table))
        self.conn.commit()
        while True:
            field = input("Enter field name (enter 'exit' to exit) : ")
            if field.upper() == "EXIT":
                break
            try:
                column = safe_identifier(field)
            except ValueError:
                self._bad_identifier("field name")
                continue
            try:
                self.cur.execute("alter table {} add column {} TEXT".format(table, column))
            except sqlite3.Error:
                self._error()
            else:
                self.conn.commit()
        if input("Do you want to add values ? ").upper() == "YES":
            self.add_records()
        print()

    def add_records(self):
        table = self._prompt_identifier("Enter your table name : ", "table name")
        if table is None:
            return
        field_count = int(input("How many fields are there ? "))
        while True:
            if input("Do you want to add records ? ").upper() != "YES":
                break
            values = tuple(input("Enter Field {} Value : ".format(i + 1))
                           for i in range(field_count))
            try:
                # Through the DAO: the table name is validated and every value is
                # bound as a ? parameter — no user input is interpolated into SQL.
                insert(table, values, or_ignore=True)
            except sqlite3.Error:
                self._error()
        print()

    def search(self):
        table_name = input("Enter Table Name :")
        field_name = input("Enter field name")
        value = input("Enter field value")
        try:
            table = safe_identifier(table_name)
            field = safe_identifier(field_name)
        except ValueError:
            self._bad_identifier("table or field name")
            print()
            return
        # Identifiers validated above; the value is bound as a parameter.
        sql = "select * from {} where {} = ?".format(table, field)
        try:
            self.cur.execute(sql, (value,))
        except sqlite3.Error:
            self._error()
        else:
            for row in self.cur.fetchall():
                print(row)
        print()

    def show_user_table(self):
        table = self._prompt_identifier("Enter table name", "table name")
        if table is None:
            return
        try:
            self.cur.execute("select * from {}".format(table))
        except sqlite3.Error:
            self._error()
        else:
            for row in self.cur.fetchall():
                print(row)
        print()

    def _prompt_identifier(self, prompt, what):
        """Prompt for a table/column name and whitelist-validate it. Returns the
        validated name, or None (after printing guidance) if it's invalid."""
        try:
            return safe_identifier(input(prompt))
        except ValueError:
            self._bad_identifier(what)
            print()
            return None

    def creator_mode(self):
        """Create tables, add rows, or view a user table."""
        while True:
            choice = input("Do you want to ( VIEW | ADD | CREATE | QUIT ) ? ").upper()
            if choice == "CREATE":
                self.create_table()
            elif choice == "ADD":
                self.add_records()
            elif choice == "VIEW":
                answer = input("Is it a pre-determined table?").upper()
                if answer == "YES":
                    print("Please use the designated commands to view those tables")
                    break
                elif answer == "NO":
                    self.show_user_table()
            elif choice == "QUIT":
                print("P.A.N.D.A : Exiting CREATOR MODE...")
                break
            else:
                print("P.A.N.D.A : Wrong input.")
                print("P.A.N.D.A : Try again.")
        print()

    # --- main loop ---------------------------------------------------------

    def run(self):
        print("Welcome to the Panda Vault. ")
        print("Here, you can browse TDR cases and manage your own records.")
        print()
        print("CREATOR MODE : Create and access your own tables ")
        print()
        while True:
            choice = input(
                "What do you want to access ( CASES | CREATOR | SHOW | SEARCH | HELP )?").upper()
            if "CASES" in choice:
                self.cases()
                print()
            elif "CREATOR" in choice:
                self.creator_mode()
            elif "SHOW" in choice:
                self.show_tables()
                print()
            elif "HELP" in choice:
                self.help()
                print()
            elif "SEARCH" in choice:
                self.search()
                print()
            elif choice == "QUIT":
                print("Exiting the PandaVault ...")
                break


def DATABASE():
    """Public entry point: run the interactive vault shell (see VaultShell)."""
    VaultShell().run()
