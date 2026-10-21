import sqlite3, json, os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "osint.db")

def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS searches(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            query TEXT NOT NULL,
            created_at TEXT NOT NULL,
            result TEXT NOT NULL)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_searches_type ON searches(type)")

def add_search(type_, query, result):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _conn() as c:
        cur = c.execute("INSERT INTO searches(type,query,created_at,result) VALUES(?,?,?,?)",
                        (type_, query, now, json.dumps(result)))
        return cur.lastrowid

def list_searches(limit=500):
    with _conn() as c:
        rows = c.execute("SELECT * FROM searches ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

def get_search(sid):
    with _conn() as c:
        row = c.execute("SELECT * FROM searches WHERE id=?", (sid,)).fetchone()
    return dict(row) if row else None


def delete_searches(ids):
    with _conn() as c:
        c.executemany("DELETE FROM searches WHERE id=?", [(int(i),) for i in ids])
    return len(ids)
