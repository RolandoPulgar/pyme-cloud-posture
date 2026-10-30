import datetime
from dataclasses import dataclass, field
from typing import List, Dict
from .rules import Finding, Severity, SEVERITY_WEIGHTS
from .modules import (
    check_email_authentication,
    check_mail_infrastructure,
    check_web_tls_posture
)

@dataclass
class ScanResult:
    domain: str
    timestamp: str
    score: int
    resilience_level: str
    summary: Dict[str, int]
    findings: List[Finding] = field(default_factory=list)

class PyMECloudAuditor:
    def __init__(self, domain: str):
        # Clean domain
        d = domain.strip().lower()
        if d.startswith("http://"):
            d = d[7:]
        elif d.startswith("https://"):
            d = d[8:]
        self.domain = d.split("/")[0]

    def run_scan(self) -> ScanResult:
        findings = []

        # 1. Email Auth (SPF, DMARC, DKIM)
        findings.extend(check_email_authentication(self.domain))

        # 2. Mail Infrastructure (MX)
        findings.extend(check_mail_infrastructure(self.domain))

        # 3. Web & TLS Posture
        findings.extend(check_web_tls_posture(self.domain))

        # Metrics calculation
        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "PASSED": 0,
            "TOTAL_CHECKS": len(findings)
        }

        penalty = 0
        for f in findings:
            if f.status in ["FAIL", "WARN"]:
                sev_name = f.severity.value
                if sev_name in summary:
                    summary[sev_name] += 1
                penalty += SEVERITY_WEIGHTS.get(f.severity, 0)
            elif f.status == "PASS":
                summary["PASSED"] += 1

        score = max(0, min(100, 100 - penalty))

        if score >= 90:
            resilience = "Excelente - Alta Protección Anti-Spoofing"
        elif score >= 75:
            resilience = "Buena - Riesgo Moderado de Suplantación"
        elif score >= 50:
            resilience = "Aceptable - Requiere Endurecimiento Urgente"
        else:
            resilience = "Crítica - Vulnerable a Phishing y Suplantación Directa"

        return ScanResult(
            domain=self.domain,
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            score=score,
            resilience_level=resilience,
            summary=summary,
            findings=findings
        )
