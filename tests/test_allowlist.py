import pytest
from pathlib import Path
from src.database.db import Database
from src.security.allowlist import AllowlistService, normalize_domain


@pytest.fixture
async def temp_db(tmp_path: Path):
    db_file = tmp_path / "test_sec.db"
    db = Database(db_file)
    await db.init_db()
    return db


def test_normalize_domain():
    assert normalize_domain("example.com") == "example.com"
    assert normalize_domain("https://example.com") == "example.com"
    assert normalize_domain("http://sub.example.com:8443/login?q=1") == "sub.example.com"
    assert normalize_domain("  TEST.ORG/path/  ") == "test.org"
    assert normalize_domain("") == ""


@pytest.mark.asyncio
async def test_unapproved_domain_is_strictly_rejected(temp_db: Database):
    service = AllowlistService(temp_db)
    
    # Attempt check without adding to allowlist
    allowed, msg, site = await service.check_and_authorize("unauthorized-target.com", user_id=12345)
    
    assert allowed is False
    assert "Authorization Denied" in msg
    assert site is None

    # Check audit log contains rejection
    logs = await temp_db.get_recent_audit_logs(limit=5)
    assert len(logs) == 1
    assert logs[0].target_domain == "unauthorized-target.com"
    assert logs[0].allowed is False
    assert "not in approved_sites allowlist" in logs[0].reason


@pytest.mark.asyncio
async def test_approved_domain_is_authorized(temp_db: Database):
    service = AllowlistService(temp_db)

    # 1. Authorize site
    await temp_db.add_approved_site(
        domain="myproject.org",
        note="Personal portfolio project",
        added_by=12345
    )

    # 2. Check authorization
    allowed, domain, site = await service.check_and_authorize("https://myproject.org/dashboard", user_id=12345)

    assert allowed is True
    assert domain == "myproject.org"
    assert site is not None
    assert site.note == "Personal portfolio project"

    # Verify audit record
    logs = await temp_db.get_recent_audit_logs(limit=5)
    assert len(logs) == 1
    assert logs[0].target_domain == "myproject.org"
    assert logs[0].allowed is True
    assert "Approved on basis" in logs[0].reason


@pytest.mark.asyncio
async def test_revoked_domain_refuses_subsequent_scans(temp_db: Database):
    service = AllowlistService(temp_db)

    # Authorize site
    await temp_db.add_approved_site("clientcorp.com", "Client contract signed", 12345)
    allowed, _, _ = await service.check_and_authorize("clientcorp.com", 12345)
    assert allowed is True

    # Revoke site
    removed = await temp_db.remove_approved_site("clientcorp.com")
    assert removed is True

    # Subsequent scan attempt must fail
    allowed_after, msg, _ = await service.check_and_authorize("clientcorp.com", 12345)
    assert allowed_after is False
    assert "Authorization Denied" in msg
