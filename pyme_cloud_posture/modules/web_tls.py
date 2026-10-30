import ssl
import socket
import datetime
import urllib.request
from ..rules import Finding, Severity

def check_web_tls_posture(domain: str) -> list:
    findings = []
    host = domain.strip().lower()

    # 1. SSL/TLS Certificate Check
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    cert = None
    try:
        with socket.create_connection((host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        findings.append(Finding(
            id="WEB-TLS-001",
            title="Conexión HTTPS Fallida o Certificado Inválido",
            category="Web & Perimeter Security",
            severity=Severity.HIGH,
            description=f"No se pudo establecer una conexión TLS/HTTPS segura con '{host}': {str(e)}.",
            impact="Los visitantes y clientes recibirán advertencias de 'Sitio No Seguro', afectando la credibilidad y exponiendo el tráfico a interceptación.",
            remediation="Verificar que el servidor web escuche en el puerto 443 y tenga un certificado TLS válido y no autofirmado.",
            suggested_dns=None,
            status="FAIL",
            details=f"Error retornado: {str(e)}"
        ))
        return findings

    # Certificate expiration
    if cert and "notAfter" in cert:
        # Format: 'May 15 12:00:00 2026 GMT'
        expiry_str = cert["notAfter"]
        try:
            expiry_date = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_date - datetime.datetime.utcnow()).days

            if days_left < 0:
                findings.append(Finding(
                    id="WEB-TLS-002",
                    title="Certificado SSL/TLS Expirado",
                    category="Web & Perimeter Security",
                    severity=Severity.CRITICAL,
                    description=f"El certificado SSL expiró hace {abs(days_left)} días (Fecha de expiración: {expiry_str}).",
                    impact="Todos los navegadores bloquean el acceso al sitio web corporativo de la PyME.",
                    remediation="Renovar el certificado inmediatamente (mediante Let's Encrypt o entidad emisora).",
                    suggested_dns=None,
                    status="FAIL",
                    details=f"Expiró el: {expiry_str}"
                ))
            elif days_left < 21:
                findings.append(Finding(
                    id="WEB-TLS-002",
                    title="Certificado SSL/TLS Próximo a Vencer",
                    category="Web & Perimeter Security",
                    severity=Severity.HIGH,
                    description=f"El certificado SSL vencerá en {days_left} días.",
                    impact="Riesgo inminente de interrupción del portal corporativo si no se renueva a tiempo.",
                    remediation="Automatizar la renovación mediante certbot / ACME.",
                    suggested_dns=None,
                    status="WARN",
                    details=f"Días restantes: {days_left}"
                ))
            else:
                findings.append(Finding(
                    id="WEB-TLS-002",
                    title="Certificado SSL/TLS Válido y Saludable",
                    category="Web & Perimeter Security",
                    severity=Severity.PASSED,
                    description=f"Certificado SSL activo con {days_left} días de vigencia restantes.",
                    impact="El tráfico de los clientes y transacciones viaja cifrado de forma segura.",
                    remediation="Mantener monitoreo de renovación automática.",
                    suggested_dns=None,
                    status="PASS",
                    details=f"Vigente hasta {expiry_str} ({days_left} días)"
                ))
        except Exception:
            pass

    # 2. HTTP Security Headers Check (HSTS, etc.)
    try:
        req = urllib.request.Request(
            f"https://{host}",
            headers={"User-Agent": "PyME-Cloud-Posture-Scanner/1.0"}
        )
        with urllib.request.urlopen(req, timeout=6) as response:
            headers = {k.lower(): v for k, v in response.getheaders()}

            # Check HSTS (Strict-Transport-Security)
            if "strict-transport-security" in headers:
                findings.append(Finding(
                    id="WEB-HDR-001",
                    title="Encabezado HSTS (Strict-Transport-Security) Activo",
                    category="Web & Perimeter Security",
                    severity=Severity.PASSED,
                    description="El sitio fuerza conexiones HTTPS seguras impidiendo ataques de degradación SSL Strip.",
                    impact="Protege a los clientes contra ataques Man-In-The-Middle (MITM).",
                    remediation="Mantener directiva max-age >= 31536000.",
                    suggested_dns=None,
                    status="PASS",
                    details=f"HSTS: {headers.get('strict-transport-security')}"
                ))
            else:
                findings.append(Finding(
                    id="WEB-HDR-001",
                    title="Falta Encabezado de Seguridad HSTS",
                    category="Web & Perimeter Security",
                    severity=Severity.LOW,
                    description="El servidor no envía la cabecera 'Strict-Transport-Security'.",
                    impact="Los usuarios que escriban 'http://' podrían ser interceptados antes de ser redirigidos a HTTPS.",
                    remediation="Añadir 'Strict-Transport-Security: max-age=31536000; includeSubDomains' en Nginx, Apache o Cloudflare.",
                    suggested_dns=None,
                    status="WARN",
                    details="Header 'Strict-Transport-Security' ausente."
                ))
    except Exception:
        pass

    return findings
