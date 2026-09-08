import pytest
from src.core.scorer import SecurityScorer
from src.database.models import Finding, Severity


def test_scorer_perfect_score():
    findings = []
    score, grade, badge, bar = SecurityScorer.calculate_score(findings)
    assert score == 100
    assert grade == "A+"
    assert "Hardened" in badge
    assert "100/100" in bar
    assert bar.startswith("[██████████]")


def test_scorer_deductions_and_grades():
    # 1 critical (-30) -> 70 (B)
    findings = [
        Finding(
            title="Exposed .env",
            severity=Severity.CRITICAL,
            tool="Test",
            description="test",
            why_it_matters="test"
        )
    ]
    score, grade, badge, bar = SecurityScorer.calculate_score(findings)
    assert score == 70
    assert grade == "B"
    assert "Moderate" in badge

    # Add 1 High (-15) + 1 Medium (-5) -> 70 - 20 = 50 (D)
    findings.append(Finding(title="High", severity=Severity.HIGH, tool="Test", description="test", why_it_matters="test"))
    findings.append(Finding(title="Medium", severity=Severity.MEDIUM, tool="Test", description="test", why_it_matters="test"))
    score2, grade2, badge2, bar2 = SecurityScorer.calculate_score(findings)
    assert score2 == 50
    assert grade2 == "D"

    # Add 2 more Critical (-60) -> drops below 0 -> floored at 0 (F)
    findings.append(Finding(title="Crit 2", severity=Severity.CRITICAL, tool="Test", description="test", why_it_matters="test"))
    findings.append(Finding(title="Crit 3", severity=Severity.CRITICAL, tool="Test", description="test", why_it_matters="test"))
    score3, grade3, badge3, bar3 = SecurityScorer.calculate_score(findings)
    assert score3 == 0
    assert grade3 == "F"
    assert "0/100" in bar3
