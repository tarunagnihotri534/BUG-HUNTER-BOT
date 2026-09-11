import pytest
from src.core.scorer import SecurityScorer
from src.database.models import Finding, Severity


def test_scorer_perfect_score():
    findings = []
    score, grade, badge, bar, active_leak = SecurityScorer.calculate_score(findings)
    assert score == 100
    assert grade == "A+"
    assert "Hardened" in badge
    assert "100/100" in bar
    assert bar.startswith("[██████████]")
    assert active_leak is False


def test_scorer_deductions_and_critical_decoupling():
    # 1 critical -> grade clamped to F, active_leak is True, score is 100 (decoupled from crit leak)
    findings = [
        Finding(
            title="Exposed .env",
            severity=Severity.CRITICAL,
            tool="Test",
            description="test",
            why_it_matters="test"
        )
    ]
    score, grade, badge, bar, active_leak = SecurityScorer.calculate_score(findings)
    assert score == 100
    assert grade == "F"
    assert "Active Critical Leak" in badge
    assert active_leak is True

    # Add 1 High (-15) + 1 Medium (-5) -> 100 - 20 = 80
    findings.append(Finding(title="High", severity=Severity.HIGH, tool="Test", description="test", why_it_matters="test"))
    findings.append(Finding(title="Medium", severity=Severity.MEDIUM, tool="Test", description="test", why_it_matters="test"))
    score2, grade2, badge2, bar2, active_leak2 = SecurityScorer.calculate_score(findings)
    assert score2 == 80
    assert grade2 == "F"  # Still F due to active critical leak
    assert active_leak2 is True

    # When NO critical findings exist, standard scoring applies
    non_crit_findings = [
        Finding(title="High", severity=Severity.HIGH, tool="Test", description="test", why_it_matters="test"),
        Finding(title="Medium", severity=Severity.MEDIUM, tool="Test", description="test", why_it_matters="test")
    ]
    score3, grade3, badge3, bar3, active_leak3 = SecurityScorer.calculate_score(non_crit_findings)
    assert score3 == 80
    assert grade3 == "B"
    assert active_leak3 is False
