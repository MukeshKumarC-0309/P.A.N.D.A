"""
PandaVault: the interactive record-management shell.

Kept as one large DATABASE() function with nested sub-functions, preserved
from the original implementation. It works correctly as-is; splitting it into
a proper class-based structure is a natural next refactor once the rest of the
project is stable. See README.md for notes on that.

PANDA is security-only: the one built-in domain is the TDR evidence store
(browsed via CASES, which shares panda/browse.py with the top-level `cases`
command). Users can still define and query their own tables at runtime through
CREATOR / DEVELOPER mode. The database is embedded SQLite (stdlib sqlite3): a
single local file per device (config.DB_PATH), created empty on first run from
schema.sql — a zero-install, offline, per-user tool.
"""
import sqlite3

from tabulate import tabulate

from panda.db import connection as conobj, cursor as cur
from panda.db import safe_identifier as _safe_identifier
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
        print("DEVELOPER MODE:This command allows you to make changes to the record structure of the table(can only be accessed through our special passcode)")
        print("CREATOR MODE:This command allows you to create your own tables and maintain your own record")
        print("-"*100)
    def USER():
        #DEVELOPER MODE where you ( the developer ) can directly input code
        while True:
            try:
                inp=input("What do you want to do ? ")
                cur.execute(inp)
                conobj.commit()
            except Exception:
                print("P.A.N.D.A : An unexpected error has occurred.")
                print("P.A.N.D.A : Please try again.")
            inp5=input("Do you want to continue using DEVELOPER MODE ? ")
            if inp5.upper()=="YES":
                continue
            else:
                print("Exiting DEVELOPER MODE...")
                return
    def panda_create():
        ch=input("Enter table name : ")
        execute15="create table if not exists {}(Serial_No TEXT)".format(ch)
        cur.execute(execute15)
        while True:
            inp1=input("Enter field name (enter 'exit' to exit) : ")
            if inp1.upper()=="EXIT":
                break
            else:
                execute16="alter table {} add column {} TEXT".format(ch,inp1)
                try:
                    cur.execute(execute16)
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
        inp1=int(input("How many fields are there ? "))
        while True:
            a=()
            inp2=input("Do you want to add records ? ")
            if inp2.upper()=="YES":
                for i in range(inp1):
                    a+=(input("Enter Field 1 Value : "),)
                print(a)
                execute17="insert or ignore into {} values{}".format(ch,a)
                try:
                    cur.execute(execute17)
                except sqlite3.Error:
                    print("P.A.N.D.A : An unexpected error has occured")
                    print("P.A.N.D.A : Please check the values again")
                else:
                    conobj.commit()
            else:
                break
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
    print("DEVELOPER MODE : Developer-exclusive tools to work on the Vault ")
    print()
    while True:
        Choice=input("What do you want to access ( CASES | MODE | SHOW | SEARCH | HELP )?")
        if "CASES" in Choice.upper():
            CASES()
            print()
        elif "DEVELOPER MODE" in Choice.upper():
            #Executes functions to enable developer mode where developer can directly type in code
            n=0
            while n<3:
                #Uses passcode authentication to ensure security
                passcode=input("Please enter the passcode : ")
                if passcode.upper()=="ILUVPANDAS":
                    USER()
                    break
                else:
                    print("P.A.N.D.A : Incorrect Passcode.")
                    print("P.A.N.D.A : Try Again.")
                    n+=1
            if n==3:
                print("P.A.N.D.A : You are out of attempts. ACCESS DENIED. ")
            print()
        elif "CREATOR MODE" in Choice.upper():
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
