import pytest
from src.database.db import Database


@pytest.mark.asyncio
async def test_scheduled_scans_and_sites_db_methods(tmp_path):
    db_file = tmp_path / "test_sec_bot.db"
    db = Database(db_file)
    await db.init_db()

    # 1. Add approved site
    await db.add_approved_site("example.com", "Test Site", 111)
    sites = await db.get_all_active_approved_sites()
    assert len(sites) == 1
    assert sites[0].domain == "example.com"

    # 2. Add scheduled scan
    ok = await db.add_scheduled_scan("example.com", 111, 222, 24)
    assert ok is True

    schedules = await db.get_active_scheduled_scans()
    assert len(schedules) == 1
    assert schedules[0].domain == "example.com"
    assert schedules[0].interval_hours == 24
    assert schedules[0].chat_id == 222

    # 3. Update last run
    await db.update_schedule_last_run(schedules[0].id)
    schedules_updated = await db.get_active_scheduled_scans()
    assert schedules_updated[0].last_run_at is not None

    # 4. Remove scheduled scan
    removed = await db.remove_scheduled_scan("example.com", 222)
    assert removed is True
    schedules_after = await db.get_active_scheduled_scans()
    assert len(schedules_after) == 0
