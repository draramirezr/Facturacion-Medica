#!/usr/bin/env python3
"""Comprobar preparación local e-CF sin comunicarse con DGII."""

import sys

from dotenv import load_dotenv

from ecf.config import ECFConfig, ECFConfigurationError
from ecf.readiness import assess_readiness


def main():
    load_dotenv()
    try:
        config = ECFConfig.from_env()
    except ECFConfigurationError as error:
        print(f"[ERROR] Configuración inválida: {error}")
        return 1

    report = assess_readiness(config)
    print(f"Preparación e-CF — ambiente {report.environment}")
    for check in report.checks:
        marker = "OK" if check.passed else "FALTA"
        print(f"[{marker}] {check.detail}")

    print("\nVerificaciones operativas manuales:")
    for requirement in report.manual_requirements:
        print(f"- {requirement}")

    if report.ready:
        print("\nConfiguración local preparada. Esto no activa producción.")
        return 0
    print("\nLa configuración local todavía no está preparada.")
    return 2


if __name__ == "__main__":
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    raise SystemExit(main())
