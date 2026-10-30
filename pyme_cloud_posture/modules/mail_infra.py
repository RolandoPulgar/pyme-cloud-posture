import re
import subprocess
from ..rules import Finding, Severity

def query_mx(domain: str) -> list:
    records = []
    try:
        proc = subprocess.run(["nslookup", "-type=MX", domain], capture_output=True, text=True, timeout=8)
        for line in proc.stdout.splitlines():
            line = line.strip()
            # Examples: mail exchanger = 10 mail.example.com
            # or: MX preference = 10, mail exchanger = ...
            if "mail exchanger =" in line.lower():
                server = line.split("mail exchanger =")[-1].strip()
                if server:
                    records.append(server)
    except Exception:
        pass
    return records

def check_mail_infrastructure(domain: str) -> list:
    findings = []
    mx_records = query_mx(domain)

    if not mx_records:
        findings.append(Finding(
            id="INF-MX-001",
            title="Dominio Sin Registros MX Configurados",
            category="Mail Infrastructure",
            severity=Severity.HIGH,
            description=f"No se detectaron servidores de intercambio de correo (MX) para '{domain}'.",
            impact="El dominio no puede recibir correos electrónicos o se encuentra inactivo para mensajería.",
            remediation="Configurar registros MX apuntando a la infraestructura de correo de la empresa.",
            suggested_dns=None,
            status="WARN",
            details="0 servidores MX devueltos por DNS."
        ))
        return findings

    # Identify Provider
    all_mx_str = " ".join(mx_records).lower()
    provider = "Servidor Propio / Hosting Tradicional"
    if "outlook.com" in all_mx_str or "microsoft" in all_mx_str:
        provider = "Microsoft 365 / Exchange Online"
    elif "google.com" in all_mx_str or "googlemail.com" in all_mx_str:
        provider = "Google Workspace / Gmail for Business"
    elif "zoho" in all_mx_str:
        provider = "Zoho Mail"
    elif "protonmail" in all_mx_str:
        provider = "Proton Mail Bridge"

    findings.append(Finding(
        id="INF-MX-002",
        title=f"Servicio de Correo Identificado: {provider}",
        category="Mail Infrastructure",
        severity=Severity.INFO,
        description=f"El dominio gestiona su correo mediante: {provider}.",
        impact="Información de arquitectura e infraestructura.",
        remediation="Garantizar que las directivas de seguridad (MFA, auditoría de buzones) estén activas en la consola del proveedor.",
        suggested_dns=None,
        status="PASS",
        details=f"Servidores MX detectados ({len(mx_records)}): {', '.join(mx_records[:3])}"
    ))

    # Redundancy Check
    if len(mx_records) < 2 and provider == "Servidor Propio / Hosting Tradicional":
        findings.append(Finding(
            id="INF-MX-003",
            title="Falta de Redundancia en Servidores MX",
            category="Mail Infrastructure",
            severity=Severity.MEDIUM,
            description="El dominio depende de un único servidor MX para recibir correos corporativos.",
            impact="Si el servidor sufre una caída o ataque DDoS, la empresa dejará de recibir correos comerciales críticos.",
            remediation="Implementar un servidor de respaldo (MX secundario con mayor preferencia).",
            suggested_dns=None,
            status="WARN",
            details=f"Solo 1 registro MX: {mx_records[0]}"
        ))

    return findings
