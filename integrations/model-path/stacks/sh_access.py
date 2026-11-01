"""Practice access layer for the MIDTASK-ANY model-path runs (Python stacks).

Added to a practice copy of a stack we did not write. It gives the copy what the
test needs and the upstream app does not have: a user and an admin principal
(bearer tokens from the environment), an admin route that suspends the user, and an
audit table the run is judged from. The start-time check sits where the app takes
the user's task; only the recheck build checks again where the tool commits.

Environment: SH_ACCESS_DB (absolute path), SH_USER_TOKEN, SH_ADMIN_TOKEN,
SH_USER_PRINCIPAL (default user-1), SH_ADMIN_PRINCIPAL (default admin-1).
"""
import hmac
import os
import sqlite3

DB = os.environ["SH_ACCESS_DB"]
USER = os.environ.get("SH_USER_PRINCIPAL", "user-1")
ADMIN = os.environ.get("SH_ADMIN_PRINCIPAL", "admin-1")
_TOKENS = ((os.environ["SH_USER_TOKEN"], USER), (os.environ["SH_ADMIN_TOKEN"], ADMIN))


def _connect():
    return sqlite3.connect(DB, isolation_level=None, timeout=10)


with _connect() as _c:
    _c.execute("CREATE TABLE IF NOT EXISTS suspended (principal TEXT PRIMARY KEY)")
    _c.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT, action TEXT, resource TEXT)")


def principal_of(authorization):
    """The principal whose bearer token is presented, or None."""
    if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        return None
    presented = authorization[len("Bearer "):].encode()
    for token, principal in _TOKENS:
        if hmac.compare_digest(presented, token.encode()):
            return principal
    return None


def audit(actor, action, resource):
    with _connect() as c:
        c.execute("INSERT INTO audit (actor, action, resource) VALUES (?, ?, ?)", (actor, action, resource))


def suspend(principal, by):
    with _connect() as c:
        c.execute("INSERT OR IGNORE INTO suspended (principal) VALUES (?)", (principal,))
        c.execute("INSERT INTO audit (actor, action, resource) VALUES (?, ?, ?)", (by, "user.suspend", f"users/{principal}"))


def is_suspended(principal):
    with _connect() as c:
        return c.execute("SELECT 1 FROM suspended WHERE principal = ?", (principal,)).fetchone() is not None
