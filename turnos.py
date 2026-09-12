"""Reglas de dominio puras para el ciclo de atención de turnos."""

from enum import Enum
from typing import Union


class EstadoTurno(str, Enum):
    """Estados persistidos de un turno de atención."""

    EnEspera = "EnEspera"
    Llamado = "Llamado"
    EnConsulta = "EnConsulta"
    Atendido = "Atendido"
    NoPresente = "NoPresente"
    Anulado = "Anulado"


EstadoCompatible = Union[EstadoTurno, str]


TRANSICIONES_PERMITIDAS = {
    EstadoTurno.EnEspera: frozenset(
        {
            EstadoTurno.Llamado,
            EstadoTurno.Anulado,
        }
    ),
    EstadoTurno.Llamado: frozenset(
        {
            EstadoTurno.EnEspera,
            EstadoTurno.EnConsulta,
            EstadoTurno.NoPresente,
            EstadoTurno.Anulado,
        }
    ),
    EstadoTurno.EnConsulta: frozenset(
        {
            EstadoTurno.Atendido,
            EstadoTurno.Anulado,
        }
    ),
    EstadoTurno.Atendido: frozenset(),
    EstadoTurno.NoPresente: frozenset(
        {
            EstadoTurno.EnEspera,
            EstadoTurno.Anulado,
        }
    ),
    EstadoTurno.Anulado: frozenset(),
}


def normalizar_estado(estado: EstadoCompatible) -> EstadoTurno:
    """Convertir un valor persistido a ``EstadoTurno``."""

    if isinstance(estado, EstadoTurno):
        return estado
    try:
        return EstadoTurno(estado)
    except (TypeError, ValueError) as exc:
        valores = ", ".join(item.value for item in EstadoTurno)
        raise ValueError(
            f"Estado de turno inválido: {estado!r}. Valores válidos: {valores}"
        ) from exc


def transicion_permitida(
    estado_actual: EstadoCompatible,
    estado_nuevo: EstadoCompatible,
) -> bool:
    """Indicar si el cambio de estado está permitido por el dominio."""

    actual = normalizar_estado(estado_actual)
    nuevo = normalizar_estado(estado_nuevo)
    return nuevo in TRANSICIONES_PERMITIDAS[actual]


def validar_transicion(
    estado_actual: EstadoCompatible,
    estado_nuevo: EstadoCompatible,
) -> EstadoTurno:
    """Validar una transición y devolver el estado destino normalizado."""

    actual = normalizar_estado(estado_actual)
    nuevo = normalizar_estado(estado_nuevo)
    if nuevo not in TRANSICIONES_PERMITIDAS[actual]:
        raise ValueError(
            f"Transición de turno no permitida: {actual.value} -> {nuevo.value}"
        )
    return nuevo


ESTADOS_TERMINALES = frozenset(
    {
        EstadoTurno.Atendido,
        EstadoTurno.Anulado,
    }
)

