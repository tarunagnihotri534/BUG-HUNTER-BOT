from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def badge(self) -> str:
        return {
            Severity.CRITICAL: "🚨 CRITICAL",
            Severity.HIGH: "⚠️ HIGH",
            Severity.MEDIUM: "🔶 MEDIUM",
            Severity.LOW: "🔹 LOW",
            Severity.INFO: "ℹ️ INFO",
        }[self]

    @property
    def priority_rank(self) -> int:
        """Lower number = higher urgency."""
        return {
            Severity.CRITICAL: 1,
            Severity.HIGH: 2,
            Severity.MEDIUM: 3,
            Severity.LOW: 4,
            Severity.INFO: 5,
        }[self]


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass
class ApprovedSite:
    id: Optional[int]
    domain: str
    note: str
    added_by: int
    created_at: str
    is_active: bool = True


@dataclass
class AuditLog:
    id: Optional[int]
    target_domain: str
    user_id: int
    action: str
    allowed: bool
    reason: str
    timestamp: str


@dataclass
class Finding:
    title: str
    severity: Severity
    tool: str
    description: str
    why_it_matters: str
    reference_url: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


@dataclass
class ScanRecord:
    id: Optional[int]
    scan_id: str
    target_domain: str
    user_id: int
    status: ScanStatus
    started_at: str
    completed_at: Optional[str]
    summary: Dict[str, Any] = field(default_factory=dict)
    raw_output_path: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)


@dataclass
class StagingCredential:
    id: Optional[int]
    domain: str
    label: str
    username: str
    encrypted_secret: str
    notes: str
    created_at: str
