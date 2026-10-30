from ..scanner import ScanResult

def generate_html_report(result: ScanResult, output_path: str):
    score = result.score
    if score >= 80:
        score_color = "#10b981"
        score_bg = "#ecfdf5"
    elif score >= 60:
        score_color = "#f59e0b"
        score_bg = "#fffbeb"
    else:
        score_color = "#ef4444"
        score_bg = "#fef2f2"

    issues = [f for f in result.findings if f.status in ["FAIL", "WARN"]]
    passed = [f for f in result.findings if f.status == "PASS"]

    issues_html = ""
    for f in issues:
        sev = f.severity.value
        sev_style = {
            "CRITICAL": "background-color: #fee2e2; color: #991b1b; border: 1px solid #fecaca;",
            "HIGH": "background-color: #ffedd5; color: #9a3412; border: 1px solid #fed7aa;",
            "MEDIUM": "background-color: #fef3c7; color: #92400e; border: 1px solid #fde68a;",
            "LOW": "background-color: #f1f5f9; color: #475569; border: 1px solid #e2e8f0;"
        }.get(sev, "background-color: #f1f5f9; color: #475569;")

        dns_block = ""
        if f.suggested_dns:
            dns_block = f"""
            <div class="dns-box">
                <span class="dns-badge">Registro DNS Sugerido para Copiar/Pegar:</span>
                <pre class="code-box">{f.suggested_dns}</pre>
            </div>
            """

        issues_html += f"""
        <div class="finding-card" style="border-left: 4px solid {score_color};">
            <div class="finding-header">
                <div style="display:flex; align-items:center; gap: 8px;">
                    <span class="badge" style="{sev_style}">{sev}</span>
                    <span class="category-badge">{f.category}</span>
                </div>
                <span class="finding-id">{f.id}</span>
            </div>
            <h3 class="finding-title">{f.title}</h3>
            <p class="finding-desc">{f.description}</p>
            <div class="finding-impact">
                <strong>Impacto de Riesgo Corporativo:</strong> {f.impact}
            </div>
            <div class="finding-remediation">
                <strong>Plan de Mitigación:</strong> {f.remediation}
            </div>
            {dns_block}
            {f'<div class="finding-details"><strong>Detalle técnico:</strong> {f.details}</div>' if f.details else ''}
        </div>
        """

    passed_html = ""
    for f in passed:
        passed_html += f"""
        <div class="passed-item">
            <span class="check-icon">✓</span>
            <div>
                <strong>{f.title}</strong>
                <div style="font-size: 11px; color: #64748b;">{f.category} &bull; {f.description}</div>
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auditoría de Seguridad Cloud & Correo | {result.domain}</title>
    <style>
        :root {{
            --primary: #0f172a;
            --accent: #2563eb;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.5;
            padding: 32px 16px;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .header h1 {{ font-size: 20px; font-weight: 800; color: var(--primary); }}
        .header p {{ font-size: 13px; color: var(--text-muted); margin-top: 4px; }}
        
        .score-hero {{
            background: {score_bg};
            border: 1px solid {score_color}40;
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .score-box {{ display: flex; align-items: baseline; gap: 8px; }}
        .score-number {{ font-size: 54px; font-weight: 900; color: {score_color}; line-height: 1; }}
        .score-denom {{ font-size: 20px; font-weight: 700; color: var(--text-muted); }}
        .score-grade {{ font-size: 16px; font-weight: 800; color: var(--primary); margin-top: 4px; }}

        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .badge {{
            font-size: 10px;
            font-weight: 800;
            padding: 3px 8px;
            border-radius: 6px;
            text-transform: uppercase;
        }}
        .category-badge {{
            font-size: 11px;
            font-weight: 600;
            color: var(--text-muted);
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .finding-id {{ font-size: 11px; font-family: monospace; color: var(--text-muted); }}
        .finding-title {{ font-size: 15px; font-weight: 700; color: var(--primary); margin-bottom: 8px; }}
        .finding-desc {{ font-size: 13px; color: var(--text); margin-bottom: 8px; }}
        
        .finding-impact {{
            background: #f8fafc;
            border: 1px solid var(--border);
            padding: 10px 12px;
            border-radius: 8px;
            font-size: 12px;
            margin-bottom: 10px;
            color: #334155;
        }}
        .finding-remediation {{
            background: #eff6ff;
            border: 1px solid #bfdbfe;
            padding: 10px 12px;
            border-radius: 8px;
            font-size: 12px;
            color: #1e3a8a;
        }}
        .dns-box {{
            margin-top: 10px;
            background: #fffbeb;
            border: 1px solid #fde68a;
            border-radius: 8px;
            padding: 10px 12px;
        }}
        .dns-badge {{
            font-size: 11px;
            font-weight: 700;
            color: #92400e;
            text-transform: uppercase;
        }}
        .code-box {{
            background: #0f172a;
            color: #f8fafc;
            padding: 8px 12px;
            border-radius: 6px;
            margin-top: 6px;
            font-family: Consolas, monospace;
            font-size: 11px;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .finding-details {{
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 8px;
            font-family: monospace;
        }}

        .passed-grid {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 12px;
        }}
        .passed-item {{
            display: flex;
            align-items: flex-start;
            gap: 10px;
            font-size: 12px;
        }}
        .check-icon {{
            background: #dcfce7;
            color: #15803d;
            border-radius: 50%;
            width: 18px;
            height: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 11px;
            flex-shrink: 0;
            margin-top: 2px;
        }}

        .footer {{
            text-align: center;
            margin-top: 40px;
            font-size: 12px;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            padding-top: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div>
                <h1>Auditoría de Seguridad Cloud & Correo Corporativo</h1>
                <p>Dominio Analizado: <strong>{result.domain}</strong> &bull; Fecha: {result.timestamp}</p>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 12px; font-weight: 700; color: var(--primary);">PyME-Cloud-Posture</div>
                <div style="font-size: 11px; color: var(--text-muted);">Auditor: Rolando Pulgar</div>
            </div>
        </div>

        <!-- Score Hero -->
        <div class="score-hero">
            <div>
                <div class="score-box">
                    <span class="score-number">{score}</span>
                    <span class="score-denom">/ 100</span>
                </div>
                <div class="score-grade">{result.resilience_level}</div>
            </div>
            <div style="display:flex; gap:12px; flex-wrap:wrap;">
                <div style="background:#fff; border:1px solid #e2e8f0; padding:8px 12px; border-radius:10px; font-size:12px; font-weight:700;">
                    Alertas Críticas/Altas: <span style="color:#ef4444;">{result.summary['CRITICAL'] + result.summary['HIGH']}</span>
                </div>
                <div style="background:#fff; border:1px solid #e2e8f0; padding:8px 12px; border-radius:10px; font-size:12px; font-weight:700;">
                    Controles Aprobados: <span style="color:#10b981;">{result.summary['PASSED']}</span>
                </div>
            </div>
        </div>

        <!-- Issues -->
        <h2 style="font-size:16px; font-weight:800; margin:24px 0 16px 0;">Vulnerabilidades de Configuración y Remediación Directa</h2>
        {issues_html if issues_html else '<p style="color:#10b981; font-weight:600;">No se detectaron problemas de autenticación de correo o certificados.</p>'}

        <!-- Passed -->
        <h2 style="font-size:16px; font-weight:800; margin:28px 0 16px 0;">Controles y Mecanismos de Autenticación Validados</h2>
        <div class="passed-grid">
            {passed_html}
        </div>

        <div class="footer">
            Generado automáticamente con <strong>PyME-Cloud-Posture</strong> &bull; Herramienta de auditoría de ciberseguridad cloud para PyMEs.
        </div>
    </div>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
