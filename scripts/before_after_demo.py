"""Local-only, synthetic before/after illustration. Requires explicit opt-in."""
import os
import sqlite3
import sys
from html import escape

arguments=sys.argv[1:]
if os.getenv("ENABLE_VULNERABLE_DEMO") != "1" and "--enable-demo" not in arguments:
    raise SystemExit("Disabled. Pass --enable-demo only for a local classroom demonstration.")
arguments=[arg for arg in arguments if arg!="--enable-demo"]
payload=arguments[0] if arguments else "' OR '1'='1"
db=sqlite3.connect(":memory:")
db.executescript("CREATE TABLE demo_users(username TEXT, display_name TEXT); INSERT INTO demo_users VALUES('alice','Synthetic Alice'),('bob','Synthetic Bob');")
print("BEFORE (unsafe SQL concatenation, synthetic in-memory data):")
unsafe_sql=f"SELECT username,display_name FROM demo_users WHERE username = '{payload}'"
try:
    print("Rows returned:",db.execute(unsafe_sql).fetchall())
except sqlite3.Error as error:
    print("Query rejected:",error)
print("AFTER (parameterized query):")
print("Rows returned:",db.execute("SELECT username,display_name FROM demo_users WHERE username = ?",(payload,)).fetchall())
print("XSS output example (escaped text; never inserted as HTML):",escape("<script>alert(1)</script>"))
db.close()
