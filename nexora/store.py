"""SQLite workspace database for the Nexconsole REPL.

Persists hosts, services, findings, evidence and notes per named
workspace in ``~/.nexora/nexora.db`` (or an explicit path). One single
``sqlite3.Connection`` per Store instance, ``sqlite3.Row`` row factory,
commit-per-write. Every public method is best-effort: once the Store is
constructed, no method should ever raise into the console — failures
degrade to no-ops / empty lists. The only exception that may escape is
the invalid-workspace-name ``ValueError`` from ``use_workspace``.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

_WS_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

DEFAULT_DB = os.path.join(os.path.expanduser("~"), ".nexora", "nexora.db")


def _now() -> str:
    """UTC timestamp, second precision, ISO-8601 with a trailing Z."""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _json_text(data: Any) -> Optional[str]:
    """Serialize ``data`` to JSON text; strings pass through as-is."""
    if data is None:
        return None
    if isinstance(data, str):
        return data
    try:
        return json.dumps(data, ensure_ascii=False, default=str)
    except Exception:
        try:
            return json.dumps({"repr": repr(data)[:2000]})
        except Exception:
            return None


class Store:
    """Workspace-scoped SQLite store (hosts/services/findings/evidence/notes)."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = str(path) if path else DEFAULT_DB
        directory = os.path.dirname(os.path.abspath(self.path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._workspace = "default"
        self._create()
        try:
            self._conn.execute(
                "INSERT OR IGNORE INTO workspaces(name, created) VALUES (?, ?)",
                ("default", _now()))
            self._conn.commit()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def _create(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS workspaces (
                name    TEXT PRIMARY KEY,
                created TEXT
            );
            CREATE TABLE IF NOT EXISTS hosts (
                workspace  TEXT NOT NULL,
                host       TEXT NOT NULL,
                ip         TEXT,
                module     TEXT DEFAULT '',
                first_seen TEXT,
                last_seen  TEXT,
                notes      TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_hosts_workspace ON hosts(workspace);
            CREATE TABLE IF NOT EXISTS services (
                workspace TEXT,
                host      TEXT,
                port      INTEGER,
                proto     TEXT,
                name      TEXT,
                info      TEXT,
                created   TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                workspace TEXT,
                module    TEXT,
                target    TEXT,
                severity  TEXT,
                title     TEXT,
                detail    TEXT,
                data      TEXT,
                created   TEXT
            );
            CREATE TABLE IF NOT EXISTS evidence (
                workspace TEXT,
                kind      TEXT,
                source    TEXT,
                target    TEXT,
                data      TEXT,
                created   TEXT
            );
            CREATE TABLE IF NOT EXISTS notes (
                workspace TEXT,
                body      TEXT,
                created   TEXT
            );
            """
        )
        self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.commit()
        except Exception:
            pass
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # Workspaces
    # ------------------------------------------------------------------ #
    def use_workspace(self, name: str) -> str:
        """Switch the active workspace; validates the name (may raise)."""
        clean = str(name or "").strip()
        if not _WS_RE.match(clean):
            raise ValueError(
                "invalid workspace name: %r (allowed: letters, digits, "
                "'.', '_', '-'; 1-64 chars)" % (name,))
        try:
            self._conn.execute(
                "INSERT OR IGNORE INTO workspaces(name, created) VALUES (?, ?)",
                (clean, _now()))
            row = self._conn.execute(
                "SELECT name FROM workspaces WHERE name = ?",
                (clean,)).fetchone()
            self._workspace = row["name"] if row else clean
            self._conn.commit()
        except Exception:
            self._workspace = clean
        return self._workspace

    def list_workspaces(self) -> List[str]:
        try:
            rows = self._conn.execute(
                "SELECT name FROM workspaces ORDER BY name").fetchall()
            return [str(r["name"]) for r in rows]
        except Exception:
            return [self._workspace]

    def current_workspace(self) -> str:
        return self._workspace

    # ------------------------------------------------------------------ #
    # Writes (best-effort)
    # ------------------------------------------------------------------ #
    def add_host(self, host: str, ip: Optional[str] = None,
                 module: str = "") -> None:
        host = str(host or "").strip()
        if not host:
            return
        try:
            now = _now()
            row = self._conn.execute(
                "SELECT ip FROM hosts WHERE workspace = ? AND host = ?",
                (self._workspace, host)).fetchone()
            if row is not None:
                new_ip = str(ip) if ip else row["ip"]
                self._conn.execute(
                    "UPDATE hosts SET ip = ?, last_seen = ? "
                    "WHERE workspace = ? AND host = ?",
                    (new_ip, now, self._workspace, host))
            else:
                self._conn.execute(
                    "INSERT INTO hosts(workspace, host, ip, module, "
                    "first_seen, last_seen, notes) VALUES (?, ?, ?, ?, ?, ?, '')",
                    (self._workspace, host, str(ip) if ip else None,
                     str(module or ""), now, now))
            self._conn.commit()
        except Exception:
            pass

    def add_service(self, host: str, port: int, proto: str = "tcp",
                    name: str = "", info: str = "") -> None:
        try:
            self._conn.execute(
                "INSERT INTO services(workspace, host, port, proto, name, "
                "info, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (self._workspace, str(host or ""), int(port),
                 str(proto or "tcp"), str(name or ""), str(info or ""), _now()))
            self._conn.commit()
        except Exception:
            pass

    def add_finding(self, module: str, target: str, severity: str,
                    title: str, detail: str = "", data: Any = None) -> None:
        try:
            self._conn.execute(
                "INSERT INTO findings(workspace, module, target, severity, "
                "title, detail, data, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (self._workspace, str(module or ""), str(target or ""),
                 str(severity or "INFO").upper(), str(title or ""),
                 str(detail or ""), _json_text(data), _now()))
            self._conn.commit()
        except Exception:
            pass

    def add_evidence(self, kind: str, source: str, target: str,
                     data: Any) -> None:
        try:
            self._conn.execute(
                "INSERT INTO evidence(workspace, kind, source, target, data, "
                "created) VALUES (?, ?, ?, ?, ?, ?)",
                (self._workspace, str(kind or ""), str(source or ""),
                 str(target or ""), _json_text(data), _now()))
            self._conn.commit()
        except Exception:
            pass

    def add_note(self, body: str) -> None:
        body = str(body or "").strip()
        if not body:
            return
        try:
            self._conn.execute(
                "INSERT INTO notes(workspace, body, created) VALUES (?, ?, ?)",
                (self._workspace, body, _now()))
            self._conn.commit()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Reads (best-effort)
    # ------------------------------------------------------------------ #
    def findings(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            if severity:
                cur = self._conn.execute(
                    "SELECT module, target, severity, title, detail, data, "
                    "created FROM findings WHERE workspace = ? AND severity = ? "
                    "ORDER BY created DESC, rowid DESC LIMIT ?",
                    (self._workspace, str(severity).upper(), int(limit)))
            else:
                cur = self._conn.execute(
                    "SELECT module, target, severity, title, detail, data, "
                    "created FROM findings WHERE workspace = ? "
                    "ORDER BY created DESC, rowid DESC LIMIT ?",
                    (self._workspace, int(limit)))
            out = [dict(r) for r in cur.fetchall()]
        except Exception:
            pass
        return out

    def hosts_list(self, limit: int = 200) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            cur = self._conn.execute(
                "SELECT host, ip, module, first_seen, last_seen FROM hosts "
                "WHERE workspace = ? ORDER BY last_seen DESC, host LIMIT ?",
                (self._workspace, int(limit)))
            out = [dict(r) for r in cur.fetchall()]
        except Exception:
            pass
        return out

    def services_list(self, limit: int = 200) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            cur = self._conn.execute(
                "SELECT host, port, proto, name, info, created FROM services "
                "WHERE workspace = ? ORDER BY host, port LIMIT ?",
                (self._workspace, int(limit)))
            out = [dict(r) for r in cur.fetchall()]
        except Exception:
            pass
        return out

    def notes_list(self, limit: int = 50) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            cur = self._conn.execute(
                "SELECT body, created FROM notes WHERE workspace = ? "
                "ORDER BY created DESC, rowid DESC LIMIT ?",
                (self._workspace, int(limit)))
            out = [dict(r) for r in cur.fetchall()]
        except Exception:
            pass
        return out

    def evidence_list(self, limit: int = 200) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            cur = self._conn.execute(
                "SELECT kind, source, target, data, created FROM evidence "
                "WHERE workspace = ? ORDER BY created DESC, rowid DESC LIMIT ?",
                (self._workspace, int(limit)))
            out = [dict(r) for r in cur.fetchall()]
        except Exception:
            pass
        return out

    def search(self, term: str, limit: int = 50) -> List[Dict[str, Any]]:
        """LIKE %term% over findings/evidence/hosts/notes, tagged by source."""
        out: List[Dict[str, Any]] = []
        pattern = "%%%s%%" % (term or "",)
        try:
            queries = (
                ("findings",
                 "SELECT module, target, severity, title, detail, created "
                 "FROM findings WHERE workspace = ? AND (title LIKE ? OR "
                 "detail LIKE ? OR target LIKE ?) ORDER BY created DESC LIMIT ?",
                 (self._workspace, pattern, pattern, pattern, int(limit))),
                ("evidence",
                 "SELECT kind, source, target, data, created FROM evidence "
                 "WHERE workspace = ? AND (data LIKE ? OR target LIKE ?) "
                 "ORDER BY created DESC LIMIT ?",
                 (self._workspace, pattern, pattern, int(limit))),
                ("hosts",
                 "SELECT host, ip, module, last_seen FROM hosts "
                 "WHERE workspace = ? AND (host LIKE ? OR ip LIKE ?) "
                 "ORDER BY last_seen DESC LIMIT ?",
                 (self._workspace, pattern, pattern, int(limit))),
                ("notes",
                 "SELECT body, created FROM notes WHERE workspace = ? AND "
                 "body LIKE ? ORDER BY created DESC LIMIT ?",
                 (self._workspace, pattern, int(limit))),
            )
            for source, sql, params in queries:
                for row in self._conn.execute(sql, params).fetchall():
                    entry = dict(row)
                    entry["source"] = source
                    out.append(entry)
        except Exception:
            pass
        return out[: int(limit)]

    def summary(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"workspace": self._workspace}
        try:
            for table in ("hosts", "services", "findings", "evidence", "notes"):
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM %s WHERE workspace = ?" % table,
                    (self._workspace,)).fetchone()
                out[table] = int(row["n"]) if row else 0
        except Exception:
            pass
        return out

    def export_json(self, path: str) -> str:
        """Atomically dump every current-workspace table to ``path``."""
        data = {
            "nexora_store_export": 1,
            "exported_at": _now(),
            "workspace": self._workspace,
            "summary": self.summary(),
            "hosts": self.hosts_list(limit=1000000),
            "services": self.services_list(limit=1000000),
            "findings": self.findings(limit=1000000),
            "evidence": self.evidence_list(limit=1000000),
            "notes": self.notes_list(limit=1000000),
        }
        target = os.path.abspath(str(path))
        directory = os.path.dirname(target)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = target + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2, default=str)
        os.replace(tmp, target)
        return target
