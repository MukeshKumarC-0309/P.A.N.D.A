"""
PandaVault: the interactive record-management shell.

Kept as one large DATABASE() function with nested sub-functions, preserved
from the original implementation. It works correctly as-is; splitting it into
a proper class-based structure is a natural next refactor once the rest of the
project is stable. See README.md for notes on that.

PANDA is security-only: the one built-in domain is the TDR evidence store
(browsed via CASES, which shares panda/browse.py with the top-level `cases`
command). Users can still define and query their own tables at runtime through
CREATOR mode — all of it goes through the validated DAO, never raw SQL on user
input. The database is embedded SQLite (stdlib sqlite3): a
single local file per device (config.DB_PATH), created empty on first run from
schema.sql — a zero-install, offline, per-user tool.
"""
import sqlite3

from tabulate import tabulate

from panda.db import connection as conobj, cursor as cur
from panda.db import safe_identifier as _safe_identifier, insert
from panda.browse import browse_cases


def DATABASE():
    def CASES():
        # TDR evidence store: browse stored cases, filter by severity, and open
        # a case's detections and incident reports. Shares one implementation
        # with the top-level `cases` command (see panda/browse.py).
        browse_cases()
    def SHOW_TABLES():
        #To display all the tables stored in the vault
        cur.execute("select name from sqlite_master where type='table' order by name")
        r23=cur.fetchall()
        conobj.commit()
        header7=["Tables"]
        print(tabulate(r23,headers=header7,tablefmt="grid"))
        print()
    def HELP():
        #PANDA HELPDESK
        print("-"*100)
        print("Welcome to the Panda Vault. Listed below are commands that will help you  navigate through the Vault.")
        print()
        print("CASES : Browse the TDR evidence store - stored detections and incident reports, filterable by severity")
        print("\nBelow listed are commands that will help you access the features of P.A.N.D.A databases")
        print("\nSHOW TABLES:This command allows you to see what tables you have created so far")
        print("CREATOR MODE:This command allows you to create your own tables and maintain your own record")
        print("-"*100)
    def panda_create():
        ch=input("Enter table name : ")
        try:
            table=_safe_identifier(ch)
        except ValueError:
            print("P.A.N.D.A : Invalid table name.")
            print("P.A.N.D.A : Use letters, digits and underscores only.")
            print()
            return
        # Identifiers can't be bound as parameters, so validate them against the
        # whitelist before interpolating — no raw user input reaches the DDL.
        cur.execute("create table if not exists {}(Serial_No TEXT)".format(table))
        conobj.commit()
        while True:
            inp1=input("Enter field name (enter 'exit' to exit) : ")
            if inp1.upper()=="EXIT":
                break
            try:
                column=_safe_identifier(inp1)
            except ValueError:
                print("P.A.N.D.A : Invalid field name.")
                print("P.A.N.D.A : Use letters, digits and underscores only.")
                continue
            try:
                cur.execute("alter table {} add column {} TEXT".format(table,column))
            except sqlite3.Error:
                print("P.A.N.D.A : An unexpected error has occured")
                print("P.A.N.D.A : Please check the values again")
            else:
                conobj.commit()
        ch2=input("Do you want to add values ? ")
        if ch2.upper()=="YES":
            panda_add()
        print()
    def panda_add():
        ch=input("Enter your table name : ")
        try:
            table=_safe_identifier(ch)
        except ValueError:
            print("P.A.N.D.A : Invalid table name.")
            print("P.A.N.D.A : Use letters, digits and underscores only.")
            print()
            return
        inp1=int(input("How many fields are there ? "))
        while True:
            inp2=input("Do you want to add records ? ")
            if inp2.upper()!="YES":
                break
            values=tuple(input("Enter Field {} Value : ".format(i+1)) for i in range(inp1))
            try:
                # Through the DAO: the table name is validated and every value is
                # bound as a ? parameter — no user input is interpolated into SQL.
                insert(table, values, or_ignore=True)
            except sqlite3.Error:
                print("P.A.N.D.A : An unexpected error has occured")
                print("P.A.N.D.A : Please check the values again")
        print()
    def SEARCH():
        inp7=input("Enter Table Name :")
        field1=input("Enter field name")
        val=input("Enter field value")
        try:
            table=_safe_identifier(inp7)
            field=_safe_identifier(field1)
        except ValueError:
            print("P.A.N.D.A : Invalid table or field name.")
            print("P.A.N.D.A : Use letters, digits and underscores only.")
            print()
            return
        # Identifiers validated above; the value is bound as a parameter.
        execute19="select * from {} where {} = ?".format(table,field)
        try:
            cur.execute(execute19,(val,))
        except sqlite3.Error:
            print("P.A.N.D.A : An unexpected error has occured")
            print("P.A.N.D.A : Please check the values again")
        else:
            r25=cur.fetchall()
            for i in r25:
                print(i)
        print()
    def SHOW():
        inp8=input("Enter table name")
        try:
            table=_safe_identifier(inp8)
        except ValueError:
            print("P.A.N.D.A : Invalid table name.")
            print("P.A.N.D.A : Use letters, digits and underscores only.")
            print()
            return
        execute20="select * from {}".format(table)
        try:
            cur.execute(execute20)
        except sqlite3.Error:
            print("P.A.N.D.A : An unexpected error has occured")
            print("P.A.N.D.A : Please check the values again")
        else:
            r26=cur.fetchall()
            for i in r26:
                print(i)
        print()
    #Main Block
    print("Welcome to the Panda Vault. ")
    print("Here, you can browse TDR cases and manage your own records.")
    print()
    print("CREATOR MODE : Create and access your own tables ")
    print()
    while True:
        Choice=input("What do you want to access ( CASES | CREATOR | SHOW | SEARCH | HELP )?")
        if "CASES" in Choice.upper():
            CASES()
            print()
        elif "CREATOR" in Choice.upper():
            #The creator mode asks for input from user, then accordingly calls functions to
            #create a new table, add a record to existing table, view tables or quit.
            while True:
                inp2=input("Do you want to ( VIEW | ADD | CREATE | QUIT ) ? ")
                if inp2.upper()=="CREATE":
                    panda_create()
                elif inp2.upper()=="ADD":
                    panda_add()
                elif inp2.upper()=="VIEW":
                    inp3=input("Is it a pre-determined table?")
                    if inp3.upper()=="YES":
                        print("Please use the designated commands to view those tables")
                        break
                    elif inp3.upper()=="NO":
                        SHOW()
                elif inp2.upper()=="QUIT":
                    print("P.A.N.D.A : Exiting CREATOR MODE...")
                    break
                else:
                    print("P.A.N.D.A : Wrong input.")
                    print("P.A.N.D.A : Try again.")
            print()
        elif "SHOW" in Choice.upper():
            SHOW_TABLES()
            print()
        elif "HELP" in Choice.upper():
            HELP()
            print()
        elif "SEARCH" in Choice.upper():
            SEARCH()
            print()
        elif Choice.upper()=="QUIT":
            print("Exiting the PandaVault ...")
            break
