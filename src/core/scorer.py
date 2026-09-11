from typing import List, Dict, Any, Tuple
from ..database.models import Finding, Severity


class SecurityScorer:
    """
    Computes an objective 0-100 Security Health Score and letter grade
    based on the presence and severity of findings.
    """

    CRITICAL_PENALTY = 30
    HIGH_PENALTY = 15
    MEDIUM_PENALTY = 5
    LOW_PENALTY = 1

    @classmethod
    def calculate_score(cls, findings: List[Finding]) -> Tuple[int, str, str, str, bool]:
        """
        Calculate score from findings.
        Returns: (score, grade, badge, progress_bar, active_leak)
        - The numeric score measures baseline posture/hardening (deductions from high/med/low).
        - Any CRITICAL finding forces the overall grade to F and sets active_leak = True.
        """
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)

        # Baseline posture score excludes critical leak averaging
        deductions = (
            (high_count * cls.HIGH_PENALTY) +
            (med_count * cls.MEDIUM_PENALTY) +
            (low_count * cls.LOW_PENALTY)
        )

        score = max(0, 100 - deductions)
        active_leak = crit_count > 0

        # If any CRITICAL finding exists, overall grade is forced to F
        if active_leak:
            grade = "F"
            badge = "🚨 F (Active Critical Leak Detected)"
        elif score >= 95:
            grade = "A+"
            badge = "🟢 A+ (Hardened)"
        elif score >= 85:
            grade = "A"
            badge = "🟢 A (Strong)"
        elif score >= 70:
            grade = "B"
            badge = "🟡 B (Moderate)"
        elif score >= 55:
            grade = "C"
            badge = "🟠 C (At Risk)"
        elif score >= 40:
            grade = "D"
            badge = "🔴 D (High Risk)"
        else:
            grade = "F"
            badge = "🚨 F (Substandard Posture)"

        # 10-block progress bar
        filled_blocks = round(score / 10)
        empty_blocks = 10 - filled_blocks
        progress_bar = f"[{'█' * filled_blocks}{'░' * empty_blocks}] {score}/100"

        return score, grade, badge, progress_bar, active_leak

    @classmethod
    def calculate_score_from_summary(cls, summary: Dict[str, Any]) -> Tuple[int, str, str, str, bool]:
        """Calculate score from persisted summary dict."""
        crit_count = summary.get("critical", 0)
        high_count = summary.get("high", 0)
        med_count = summary.get("medium", 0)

        deductions = (
            (high_count * cls.HIGH_PENALTY) +
            (med_count * cls.MEDIUM_PENALTY)
        )

        score = max(0, 100 - deductions)
        active_leak = crit_count > 0

        if active_leak:
            grade = "F"
            badge = "🚨 F (Active Critical Leak Detected)"
        elif score >= 95:
            grade = "A+"
            badge = "🟢 A+ (Hardened)"
        elif score >= 85:
            grade = "A"
            badge = "🟢 A (Strong)"
        elif score >= 70:
            grade = "B"
            badge = "🟡 B (Moderate)"
        elif score >= 55:
            grade = "C"
            badge = "🟠 C (At Risk)"
        elif score >= 40:
            grade = "D"
            badge = "🔴 D (High Risk)"
        else:
            grade = "F"
            badge = "🚨 F (Substandard Posture)"

        filled_blocks = round(score / 10)
        empty_blocks = 10 - filled_blocks
        progress_bar = f"[{'█' * filled_blocks}{'░' * empty_blocks}] {score}/100"

        return score, grade, badge, progress_bar, active_leak
