import json
from ..scanner import ScanResult

def generate_json_report(result: ScanResult, output_path: str):
    data = {
        "metadata": {
            "tool": "PyME-Cloud-Posture",
            "version": "1.0.0",
            "target_domain": result.domain,
            "timestamp": result.timestamp
        },
        "assessment": {
            "score": result.score,
            "resilience_level": result.resilience_level,
            "summary": result.summary
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.value,
                "status": f.status,
                "description": f.description,
                "impact": f.impact,
                "remediation": f.remediation,
                "suggested_dns": f.suggested_dns,
                "details": f.details
            } for f in result.findings
        ]
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
