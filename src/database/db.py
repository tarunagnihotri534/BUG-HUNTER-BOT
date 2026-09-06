import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
import aiosqlite

from .models import ApprovedSite, AuditLog, Finding, ScanRecord, Severity, ScanStatus


class Database:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    async def init_db(self) -> None:
        """Create database tables and indices if they do not exist."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("""
                CREATE TABLE IF NOT EXISTS approved_sites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    note TEXT NOT NULL,
                    added_by INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1
                );
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_domain TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    target_domain TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    summary TEXT,
                    raw_output_path TEXT
                );
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    why_it_matters TEXT NOT NULL,
                    reference_url TEXT,
                    raw_details TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS staging_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    label TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_secret TEXT NOT NULL,
                    notes TEXT,
                    created_at TEXT NOT NULL
                );
            """)

            # Indices for performance
            await db.execute("CREATE INDEX IF NOT EXISTS idx_approved_domain ON approved_sites(domain);")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_audit_domain ON audit_logs(target_domain);")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(target_domain);")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);")

            await db.commit()

    # --- Approved Sites CRUD ---
    async def add_approved_site(self, domain: str, note: str, added_by: int) -> bool:
        """Add or re-activate an approved site."""
        now = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO approved_sites (domain, note, added_by, created_at, is_active)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(domain) DO UPDATE SET
                    note = excluded.note,
                    added_by = excluded.added_by,
                    created_at = excluded.created_at,
                    is_active = 1;
            """, (domain.lower().strip(), note, added_by, now))
            await db.commit()
            return True

    async def remove_approved_site(self, domain: str) -> bool:
        """Deactivate an approved site."""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                UPDATE approved_sites
                SET is_active = 0
                WHERE domain = ? AND is_active = 1;
            """, (domain.lower().strip(),))
            await db.commit()
            return cursor.rowcount > 0

    async def get_approved_site(self, domain: str) -> Optional[ApprovedSite]:
        """Fetch active approved site by domain."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT id, domain, note, added_by, created_at, is_active
                FROM approved_sites
                WHERE domain = ? AND is_active = 1;
            """, (domain.lower().strip(),))
            row = await cursor.fetchone()
            if not row:
                return None
            return ApprovedSite(
                id=row["id"],
                domain=row["domain"],
                note=row["note"],
                added_by=row["added_by"],
                created_at=row["created_at"],
                is_active=bool(row["is_active"])
            )

    async def list_approved_sites(self, active_only: bool = True) -> List[ApprovedSite]:
        """List all approved sites."""
        query = "SELECT id, domain, note, added_by, created_at, is_active FROM approved_sites"
        if active_only:
            query += " WHERE is_active = 1 ORDER BY domain ASC"
        else:
            query += " ORDER BY domain ASC"

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(query)
            rows = await cursor.fetchall()
            return [
                ApprovedSite(
                    id=row["id"],
                    domain=row["domain"],
                    note=row["note"],
                    added_by=row["added_by"],
                    created_at=row["created_at"],
                    is_active=bool(row["is_active"])
                )
                for row in rows
            ]

    # --- Audit Logging ---
    async def add_audit_log(self, target_domain: str, user_id: int, action: str, allowed: bool, reason: str) -> None:
        """Record an audit trail event for security tracking."""
        now = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO audit_logs (target_domain, user_id, action, allowed, reason, timestamp)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (target_domain.lower().strip(), user_id, action, 1 if allowed else 0, reason, now))
            await db.commit()

    async def get_recent_audit_logs(self, limit: int = 10) -> List[AuditLog]:
        """Retrieve recent audit logs."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT id, target_domain, user_id, action, allowed, reason, timestamp
                FROM audit_logs
                ORDER BY id DESC
                LIMIT ?;
            """, (limit,))
            rows = await cursor.fetchall()
            return [
                AuditLog(
                    id=row["id"],
                    target_domain=row["target_domain"],
                    user_id=row["user_id"],
                    action=row["action"],
                    allowed=bool(row["allowed"]),
                    reason=row["reason"],
                    timestamp=row["timestamp"]
                )
                for row in rows
            ]

    # --- Scan Management & History ---
    async def create_scan(self, scan_id: str, target_domain: str, user_id: int) -> None:
        """Register a new scan job in PENDING status."""
        now = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO scans (scan_id, target_domain, user_id, status, started_at)
                VALUES (?, ?, ?, ?, ?);
            """, (scan_id, target_domain.lower().strip(), user_id, ScanStatus.PENDING.value, now))
            await db.commit()

    async def update_scan_status(
        self,
        scan_id: str,
        status: ScanStatus,
        summary: Optional[Dict[str, Any]] = None,
        raw_output_path: Optional[str] = None
    ) -> None:
        """Update scan status and final summary."""
        now = datetime.now(timezone.utc).isoformat() if status in (ScanStatus.COMPLETED, ScanStatus.FAILED) else None
        summary_str = json.dumps(summary) if summary else None

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE scans
                SET status = ?,
                    completed_at = COALESCE(?, completed_at),
                    summary = COALESCE(?, summary),
                    raw_output_path = COALESCE(?, raw_output_path)
                WHERE scan_id = ?;
            """, (status.value, now, summary_str, raw_output_path, scan_id))
            await db.commit()

    async def save_findings(self, scan_id: str, findings: List[Finding]) -> None:
        """Persist normalized findings for a scan."""
        if not findings:
            return
        async with aiosqlite.connect(self.db_path) as db:
            rows = [
                (
                    scan_id,
                    f.tool,
                    f.severity.value,
                    f.title,
                    f.description,
                    f.why_it_matters,
                    f.reference_url,
                    json.dumps(f.raw_data) if f.raw_data else None
                )
                for f in findings
            ]
            await db.executemany("""
                INSERT INTO findings (scan_id, tool, severity, title, description, why_it_matters, reference_url, raw_details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, rows)
            await db.commit()

    async def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        """Fetch a scan record with its findings."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT id, scan_id, target_domain, user_id, status, started_at, completed_at, summary, raw_output_path
                FROM scans
                WHERE scan_id = ?;
            """, (scan_id,))
            s_row = await cursor.fetchone()
            if not s_row:
                return None

            cursor = await db.execute("""
                SELECT tool, severity, title, description, why_it_matters, reference_url, raw_details
                FROM findings
                WHERE scan_id = ?
                ORDER BY id ASC;
            """, (scan_id,))
            f_rows = await cursor.fetchall()

            findings = [
                Finding(
                    title=f["title"],
                    severity=Severity(f["severity"]),
                    tool=f["tool"],
                    description=f["description"],
                    why_it_matters=f["why_it_matters"],
                    reference_url=f["reference_url"],
                    raw_data=json.loads(f["raw_details"]) if f["raw_details"] else None
                )
                for f in f_rows
            ]

            return ScanRecord(
                id=s_row["id"],
                scan_id=s_row["scan_id"],
                target_domain=s_row["target_domain"],
                user_id=s_row["user_id"],
                status=ScanStatus(s_row["status"]),
                started_at=s_row["started_at"],
                completed_at=s_row["completed_at"],
                summary=json.loads(s_row["summary"]) if s_row["summary"] else {},
                raw_output_path=s_row["raw_output_path"],
                findings=findings
            )

    async def get_domain_history(self, domain: str, limit: int = 5) -> List[ScanRecord]:
        """Retrieve recent scan history for a target domain."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT id, scan_id, target_domain, user_id, status, started_at, completed_at, summary, raw_output_path
                FROM scans
                WHERE target_domain = ?
                ORDER BY id DESC
                LIMIT ?;
            """, (domain.lower().strip(), limit))
            rows = await cursor.fetchall()

            results = []
            for r in rows:
                results.append(ScanRecord(
                    id=r["id"],
                    scan_id=r["scan_id"],
                    target_domain=r["target_domain"],
                    user_id=r["user_id"],
                    status=ScanStatus(r["status"]),
                    started_at=r["started_at"],
                    completed_at=r["completed_at"],
                    summary=json.loads(r["summary"]) if r["summary"] else {},
                    raw_output_path=r["raw_output_path"],
                    findings=[]
                ))
            return results
