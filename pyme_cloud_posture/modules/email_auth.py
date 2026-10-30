import re
import subprocess
from ..rules import Finding, Severity

def query_txt(domain: str) -> list:
    """Queries TXT records using native nslookup without mandatory external packages."""
    records = []
    try:
        proc = subprocess.run(["nslookup", "-type=TXT", domain], capture_output=True, text=True, timeout=8)
        lines = proc.stdout.splitlines()
        for line in lines:
            line = line.strip()
            # Match text enclosed in quotes
            match = re.findall(r'"([^"]+)"', line)
            if match:
                records.append("".join(match))
            elif "text =" in line.lower():
                part = line.split("text =")[-1].strip().strip('"')
                if part:
                    records.append(part)
    except Exception:
        pass
    return records

def check_email_authentication(domain: str) -> list:
    findings = []

    # 1. SPF Check
    txt_records = query_txt(domain)
    spf_record = next((r for r in txt_records if r.lower().startswith("v=spf1")), None)

    if not spf_record:
        findings.append(Finding(
            id="EML-SPF-001",
            title="Registro SPF No Encontrado",
            category="Email Authentication",
            severity=Severity.CRITICAL,
            description=f"El dominio '{domain}' no cuenta con un registro SPF (Sender Policy Framework) publicado en DNS.",
            impact="Cualquier ciberdelincuente en el mundo puede enviar correos falsificados en nombre de tu empresa (CEO fraud, facturas falsas a clientes) sin ser bloqueado.",
            remediation="Publicar un registro TXT en DNS autoritativo que defina los servidores autorizados para enviar correos.",
            suggested_dns=f"Tipo: TXT | Host: @ | Valor: v=spf1 include:_spf.google.com ~all (O el proveedor de correo de tu empresa)",
            status="FAIL",
            details="No se encontró registro que comience con 'v=spf1'."
        ))
    else:
        # Evaluate SPF directive
        if "+all" in spf_record:
            findings.append(Finding(
                id="EML-SPF-002",
                title="Registro SPF con Directiva Peligrosa (+all)",
                category="Email Authentication",
                severity=Severity.CRITICAL,
                description="El registro SPF contiene la directiva '+all', que autoriza explícitamente a cualquier servidor de internet a enviar correos en nombre de la empresa.",
                impact="Anula completamente la protección de correo y facilita campañas de phishing utilizando la identidad de la empresa.",
                remediation="Cambiar la directiva final a '~all' (Softfail) o '-all' (Hardfail).",
                suggested_dns=f"Reemplazar '+all' por '~all' o '-all'",
                status="FAIL",
                details=f"Registro actual: {spf_record}"
            ))
        elif "-all" in spf_record:
            findings.append(Finding(
                id="EML-SPF-003",
                title="Registro SPF Estricto (-all / Hardfail)",
                category="Email Authentication",
                severity=Severity.PASSED,
                description="El registro SPF utiliza política Hardfail ('-all'), instruyendo a los servidores receptores a rechazar correos no autorizados.",
                impact="Máxima protección a nivel de SPF contra suplantación de identidad por correo.",
                remediation="Mantener y auditar periódicamente los 'include' autorizados.",
                suggested_dns=None,
                status="PASS",
                details=f"Registro SPF: {spf_record}"
            ))
        elif "~all" in spf_record:
            findings.append(Finding(
                id="EML-SPF-004",
                title="Registro SPF con Política Permisiva Softfail (~all)",
                category="Email Authentication",
                severity=Severity.MEDIUM,
                description="El registro SPF utiliza Softfail ('~all'). Los correos no autorizados son marcados como sospechosos pero usualmente no son rechazados.",
                impact="Proporciona protección parcial. Recomendado transicionar a '-all' una vez validado que todos los servicios legítimos estén incluidos.",
                remediation="Tras verificar que servicios de facturación o marketing están incluidos, cambiar a '-all'.",
                suggested_dns=f"Modificar ~all a -all",
                status="WARN",
                details=f"Registro SPF: {spf_record}"
            ))
        else:
            findings.append(Finding(
                id="EML-SPF-005",
                title="Registro SPF Presente",
                category="Email Authentication",
                severity=Severity.PASSED,
                description="El dominio cuenta con un registro SPF válido.",
                impact="Permite validar remitentes autorizados.",
                remediation="Revisar directivas periódicamente.",
                suggested_dns=None,
                status="PASS",
                details=f"Registro: {spf_record}"
            ))

    # 2. DMARC Check
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = query_txt(dmarc_domain)
    dmarc_record = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)

    if not dmarc_record:
        findings.append(Finding(
            id="EML-DMR-001",
            title="Registro DMARC Inexistente",
            category="Email Authentication",
            severity=Severity.HIGH,
            description=f"El dominio no tiene implementado DMARC (registro en '{dmarc_domain}').",
            impact="Los proveedores como Gmail, Microsoft Outlook y Yahoo marcan los correos corporativos como SPAM o no confiables. No existe visibilidad sobre intentos de phishing usando la marca de la empresa.",
            remediation="Publicar un registro DMARC iniciando con política de monitoreo ('p=none') y dirección de reportes 'rua'.",
            suggested_dns=f"Tipo: TXT | Host: _dmarc | Valor: v=DMARC1; p=none; rua=mailto:dmarc-reports@{domain}; pct=100",
            status="FAIL",
            details="No se encontró registro TXT en _dmarc."
        ))
    else:
        # Check DMARC Policy
        if "p=reject" in dmarc_record.lower():
            findings.append(Finding(
                id="EML-DMR-002",
                title="DMARC en Modo Rechazo Estricto (p=reject)",
                category="Email Authentication",
                severity=Severity.PASSED,
                description="DMARC está configurado con política 'p=reject'. Los correos falsificados son bloqueados automáticamente en el destino.",
                impact="Protección total contra Business Email Compromise (BEC) y suplantación de identidad por correo.",
                remediation="Monitorear reportes RUA para detectar nuevos servicios legítimos.",
                suggested_dns=None,
                status="PASS",
                details=f"Registro DMARC: {dmarc_record}"
            ))
        elif "p=quarantine" in dmarc_record.lower():
            findings.append(Finding(
                id="EML-DMR-003",
                title="DMARC en Modo Cuarentena (p=quarantine)",
                category="Email Authentication",
                severity=Severity.PASSED,
                description="DMARC está configurado con política 'p=quarantine'. Correos sospechosos son enviados a la carpeta de SPAM.",
                impact="Buen nivel de protección. Camino hacia política 'p=reject'.",
                remediation="Elevar la política a 'p=reject' una vez comprobada la tasa de entrega legítima.",
                suggested_dns=None,
                status="PASS",
                details=f"Registro DMARC: {dmarc_record}"
            ))
        elif "p=none" in dmarc_record.lower():
            findings.append(Finding(
                id="EML-DMR-004",
                title="DMARC en Modo Sólo Monitoreo (p=none)",
                category="Email Authentication",
                severity=Severity.MEDIUM,
                description="DMARC tiene la política 'p=none', lo que significa que NO bloquea correos fraudulentos, solo recolecta reportes.",
                impact="Los atacantes aún pueden falsificar correos exitosamente. Esta política solo debe usarse temporalmente durante la fase de auditoría inicial.",
                remediation="Actualizar la política DMARC de 'p=none' a 'p=quarantine' o 'p=reject'.",
                suggested_dns=f"Tipo: TXT | Host: _dmarc | Valor: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}; pct=100",
                status="WARN",
                details=f"Registro DMARC: {dmarc_record}"
            ))

        # Check reporting email (rua)
        if "rua=" not in dmarc_record.lower():
            findings.append(Finding(
                id="EML-DMR-005",
                title="DMARC sin Dirección de Reportes Agregados (rua)",
                category="Email Authentication",
                severity=Severity.LOW,
                description="El registro DMARC no tiene configurada la etiqueta 'rua=', impidiendo recibir métricas sobre quién intenta enviar correos usando tu dominio.",
                impact="Pérdida de visibilidad forense y telemetría sobre ciberataques contra la marca.",
                remediation="Agregar 'rua=mailto:seguridad@tudominio.cl' en el registro DMARC.",
                suggested_dns=None,
                status="WARN",
                details=f"Registro DMARC: {dmarc_record}"
            ))

    # 3. DKIM Common Selectors Check
    common_selectors = ["default", "google", "selector1", "k1", "s1"]
    found_dkim = []
    for sel in common_selectors:
        dkim_domain = f"{sel}._domainkey.{domain}"
        records = query_txt(dkim_domain)
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
            found_dkim.append(sel)

    if found_dkim:
        findings.append(Finding(
            id="EML-DKM-001",
            title=f"Firma Criptográfica DKIM Detectada",
            category="Email Authentication",
            severity=Severity.PASSED,
            description=f"Se detectaron claves públicas DKIM activas en los selectores: {', '.join(found_dkim)}.",
            impact="Garantiza que el contenido del correo no sea alterado en tránsito (Integridad y Autenticidad).",
            remediation="Rotar claves DKIM de forma anual.",
            suggested_dns=None,
            status="PASS",
            details=f"Selectores validados: {', '.join(found_dkim)}"
        ))
    else:
        findings.append(Finding(
            id="EML-DKM-002",
            title="Clave DKIM No Encontrada en Selectores Estándar",
            category="Email Authentication",
            severity=Severity.LOW,
            description="No se identificó un registro DKIM en los selectores comunes (default, google, selector1).",
            impact="Si tu proveedor utiliza un selector personalizado no hay impacto; de lo contrario, la falta de DKIM debilita la reputación del remitente.",
            remediation="Verificar en el panel de tu proveedor de correo (Google Workspace, M365, cPanel) el selector DKIM configurado.",
            suggested_dns=None,
            status="INFO",
            details=f"Selectores probados: {', '.join(common_selectors)}"
        ))

    return findings
