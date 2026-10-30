from enum import Enum
from dataclasses import dataclass
from typing import Optional

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASSED = "PASSED"

@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: Severity
    description: str
    impact: str
    remediation: str
    suggested_dns: Optional[str]
    status: str  # 'PASS', 'FAIL', 'WARN'
    details: Optional[str] = None

SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 35,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
    Severity.PASSED: 0
}
