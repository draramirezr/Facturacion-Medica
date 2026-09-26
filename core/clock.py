"""Reloj del consultorio: las citas se interpretan en hora de República Dominicana."""

import os
from datetime import datetime
from zoneinfo import ZoneInfo

ZONA_CLINICA_NOMBRE = os.getenv('APP_TIMEZONE', 'America/Santo_Domingo')


def zona_clinica():
    try:
        return ZoneInfo(ZONA_CLINICA_NOMBRE)
    except Exception:
        return ZoneInfo('America/Santo_Domingo')


def ahora_clinica():
    """Ahora en el consultorio, sin tz, para comparar con fecha/hora de la cita."""
    return datetime.now(zona_clinica()).replace(tzinfo=None)


def fecha_clinica():
    return ahora_clinica().date()
