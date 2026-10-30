import sys
import argparse

# Windows safe utf-8 stdout
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from .scanner import PyMECloudAuditor
from .reporters import generate_html_report, generate_json_report

def main():
    parser = argparse.ArgumentParser(
        description="PyME-Cloud-Posture: Auditor de Seguridad Cloud, Correo (SPF, DKIM, DMARC) y Resiliencia Anti-Spoofing."
    )
    parser.add_argument(
        "domain",
        help="Dominio corporativo a auditar (ejemplo: miempresa.cl o domain.com)."
    )
    parser.add_argument(
        "--format", "-f",
        choices=["html", "json", "all"],
        default="html",
        help="Formato del informe a generar (html, json, all)."
    )
    parser.add_argument(
        "--output", "-o",
        default="reporte_cloud_posture.html",
        help="Ruta de guardado del informe generado."
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Modo silencioso."
    )

    args = parser.parse_args()

    if not args.quiet:
        print("\n" + "=" * 65)
        print("  [+] PyME-Cloud-Posture v1.0.0 | Cloud & Email Security Auditor")
        print("      Autor: Rolando Pulgar")
        print("=" * 65)
        print(f"[*] Analizando postura de seguridad del dominio: {args.domain}...")

    auditor = PyMECloudAuditor(args.domain)
    result = auditor.run_scan()

    if not args.quiet:
        print(f"[+] Dominio objetivo        : {result.domain}")
        print(f"[+] Score de Resiliencia    : {result.score} / 100")
        print(f"[+] Nivel de Postura        : {result.resilience_level}")
        print("-" * 65)
        print(f"    - Alertas Criticas : {result.summary['CRITICAL']}")
        print(f"    - Alertas Altas    : {result.summary['HIGH']}")
        print(f"    - Alertas Medias   : {result.summary['MEDIUM']}")
        print(f"    - Pruebas Aprobadas: {result.summary['PASSED']}")
        print("-" * 65)

    if args.format in ["html", "all"]:
        html_out = args.output if args.output.endswith(".html") else f"{args.output}.html"
        generate_html_report(result, html_out)
        if not args.quiet:
            print(f"[OK] Reporte Ejecutivo HTML generado: {html_out}")

    if args.format in ["json", "all"]:
        json_out = args.output.replace(".html", ".json") if args.output.endswith(".html") else f"{args.output}.json"
        generate_json_report(result, json_out)
        if not args.quiet:
            print(f"[OK] Reporte Tecnico JSON generado   : {json_out}")

    if not args.quiet:
        print("\n[*] Auditoria cloud completada con exito.\n")

if __name__ == "__main__":
    main()
