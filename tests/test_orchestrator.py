import asyncio
import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock

from src.config import Settings
from src.database.db import Database
from src.database.models import Finding, Severity, ScanStatus
from src.core.orchestrator import ScanOrchestrator
from src.scanners.base import BaseScanner


class MockScanner(BaseScanner):
    def __init__(self, name: str, findings: list):
        super().__init__(name=name)
        self._findings = findings

    def is_available(self) -> bool:
        return True

    async def scan(self, domain: str, **kwargs):
        return self._findings


@pytest.mark.asyncio
async def test_orchestrator_full_lifecycle(tmp_path: Path):
    db_file = tmp_path / "orchestrator_test.db"
    db = Database(db_file)
    await db.init_db()

    raw_dir = tmp_path / "raw_scans"
    settings = Settings(
        TELEGRAM_BOT_TOKEN="fake_token",
        ALLOWED_TELEGRAM_USER_IDS="123",
        DB_PATH=db_file,
        RAW_OUTPUT_DIR=raw_dir
    )

    orchestrator = ScanOrchestrator(settings, db)

    # Mock finding with a Critical severity to verify immediate alert callback
    crit_finding = Finding(
        title="Exposed AWS Secret Key",
        severity=Severity.CRITICAL,
        tool="GitleaksMock",
        description="AWS Secret Key detected in commit history.",
        why_it_matters="Attacker can compromise entire cloud account."
    )
    info_finding = Finding(
        title="Valid TLS Certificate",
        severity=Severity.INFO,
        tool="TLSMock",
        description="Valid certificate.",
        why_it_matters="Operational."
    )

    orchestrator.scanners = [
        MockScanner("GitleaksMock", [crit_finding]),
        MockScanner("TLSMock", [info_finding])
    ]

    alert_called = asyncio.Event()
    completion_called = asyncio.Event()

    async def on_alert(text: str):
        assert "URGENT SECURITY ALERT" in text
        assert "Exposed AWS Secret Key" in text
        alert_called.set()

    async def on_complete(record, messages, raw_file):
        assert record.status == ScanStatus.COMPLETED
        assert len(record.findings) == 2
        assert raw_file.exists()
        completion_called.set()

    scan_id = await orchestrator.start_scan_job(
        domain="example.org",
        user_id=123,
        alert_callback=on_alert,
        completion_callback=on_complete
    )

    assert scan_id.startswith("scan_")

    # Wait for completion
    await asyncio.wait_for(completion_called.wait(), timeout=5.0)
    assert alert_called.is_set()

    # Verify database persistence
    saved_record = await db.get_scan(scan_id)
    assert saved_record is not None
    assert saved_record.status == ScanStatus.COMPLETED
    assert len(saved_record.findings) == 2
    assert saved_record.summary["critical"] == 1
    assert saved_record.summary["total"] == 2

    # Verify raw output JSON
    assert Path(saved_record.raw_output_path).exists()
    with open(saved_record.raw_output_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)
        assert raw_data["domain"] == "example.org"
        assert "GitleaksMock" in raw_data["tools_executed"]
