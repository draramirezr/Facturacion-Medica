"""Catálogo estable de permisos y roles base del sistema.

Los códigos son identificadores persistentes: pueden cambiar las etiquetas o
descripciones, pero no deben renombrarse después de asignar permisos.
"""


PERMISOS_POR_GRUPO = {
    "pacientes": (
        ("pacientes.ver", "Ver pacientes", "Consultar pacientes y sus datos generales."),
        ("pacientes.crear", "Crear pacientes", "Registrar pacientes nuevos."),
        ("pacientes.editar", "Editar pacientes", "Actualizar datos de pacientes."),
        ("pacientes.eliminar", "Eliminar pacientes", "Eliminar registros de pacientes."),
    ),
    "turnos": (
        ("turnos.ver", "Ver turnos", "Consultar turnos y colas de atención."),
        ("turnos.crear", "Crear turnos", "Registrar pacientes en una cola de atención."),
        ("turnos.llamar", "Llamar turnos", "Llamar y avanzar turnos de atención."),
        ("turnos.administrar", "Administrar turnos", "Reordenar, cancelar y gestionar cualquier turno."),
        ("turnos.pantalla", "Administrar pantallas", "Configurar pantallas públicas de turnos."),
        ("turnos.imprimir", "Imprimir turnos", "Imprimir comprobantes y listados de turnos."),
    ),
    "cola_propia": (
        ("turnos.cola_propia", "Gestionar cola propia", "Gestionar únicamente la cola asociada al médico."),
    ),
    "historia_clinica": (
        ("historia_clinica.ver", "Ver historia clínica", "Consultar el expediente clínico longitudinal."),
        ("historia_clinica.crear", "Crear historia clínica", "Registrar consultas y notas clínicas."),
        ("historia_clinica.editar", "Editar historia clínica", "Actualizar consultas y evoluciones clínicas."),
        ("historia_clinica.imprimir", "Imprimir historia clínica", "Generar impresiones del expediente clínico."),
    ),
    "recetas": (
        ("recetas.ver", "Ver recetas", "Consultar recetas médicas."),
        ("recetas.crear", "Crear recetas", "Emitir recetas médicas."),
        ("recetas.anular", "Anular recetas", "Anular recetas conservando su historial."),
        ("recetas.imprimir", "Imprimir recetas", "Generar impresiones de recetas médicas."),
    ),
    "licencias": (
        ("licencias.ver", "Ver licencias", "Consultar licencias médicas."),
        ("licencias.crear", "Crear licencias", "Emitir licencias médicas."),
        ("licencias.editar", "Editar licencias", "Actualizar licencias médicas."),
        ("licencias.anular", "Anular licencias", "Anular licencias conservando su historial."),
        ("licencias.imprimir", "Imprimir licencias", "Generar impresiones de licencias médicas."),
        ("licencias.configurar", "Configurar licencias", "Administrar los tipos de licencia médica."),
    ),
    "emergencia": (
        ("emergencia.ver", "Ver emergencias", "Consultar historias clínicas de emergencia."),
        ("emergencia.crear", "Crear emergencias", "Registrar historias clínicas de emergencia."),
        ("emergencia.imprimir", "Imprimir emergencias", "Generar impresiones de historias de emergencia."),
    ),
    "enfermeria": (
        ("enfermeria.ver", "Ver enfermería", "Consultar hojas de enfermería."),
        ("enfermeria.crear", "Crear hojas de enfermería", "Registrar hojas de enfermería."),
        ("enfermeria.imprimir", "Imprimir hojas de enfermería", "Generar impresiones de hojas de enfermería."),
    ),
    "citas": (
        ("citas.ver", "Ver citas", "Consultar la agenda de citas médicas."),
        ("citas.crear", "Crear citas", "Programar citas médicas."),
        ("citas.editar", "Editar citas", "Reprogramar y actualizar citas médicas."),
        ("citas.cancelar", "Cancelar citas", "Cancelar citas médicas."),
    ),
    "facturacion": (
        ("facturacion.ver", "Ver facturación", "Consultar pacientes pendientes, facturas y comprobantes."),
        ("facturacion.crear", "Crear facturas", "Registrar y emitir facturas."),
        ("facturacion.editar", "Editar facturas", "Actualizar borradores y datos de facturación."),
        ("facturacion.anular", "Anular facturas", "Anular facturas y comprobantes."),
        ("facturacion.imprimir", "Imprimir facturas", "Imprimir y exportar documentos de facturación."),
    ),
    "catalogos": (
        ("catalogos.ver", "Ver catálogos", "Consultar catálogos operativos."),
        ("catalogos.crear", "Crear catálogos", "Crear ARS, servicios, médicos y centros."),
        ("catalogos.editar", "Editar catálogos", "Actualizar catálogos operativos."),
        ("catalogos.eliminar", "Eliminar catálogos", "Eliminar elementos de catálogos operativos."),
    ),
    "usuarios": (
        ("usuarios.ver", "Ver usuarios", "Consultar usuarios de la empresa."),
        ("usuarios.crear", "Crear usuarios", "Registrar usuarios de la empresa."),
        ("usuarios.editar", "Editar usuarios", "Actualizar y activar usuarios de la empresa."),
        ("usuarios.eliminar", "Eliminar usuarios", "Eliminar o desactivar usuarios de la empresa."),
    ),
    "roles": (
        ("roles.ver", "Ver roles", "Consultar roles y sus permisos."),
        ("roles.crear", "Crear roles", "Crear roles personalizados."),
        ("roles.editar", "Editar roles", "Actualizar roles y asignaciones de permisos."),
        ("roles.eliminar", "Eliminar roles", "Eliminar roles personalizados."),
        ("roles.asignar", "Asignar roles", "Asignar y retirar roles a usuarios."),
    ),
    "reportes": (
        ("reportes.ver", "Ver reportes", "Consultar reportes operativos y administrativos."),
        ("reportes.exportar", "Exportar reportes", "Descargar reportes y resultados."),
    ),
    "configuracion": (
        ("configuracion.ver", "Ver configuración", "Consultar la configuración de la empresa."),
        ("configuracion.editar", "Editar configuración", "Actualizar la configuración de la empresa."),
    ),
}


PERMISOS = tuple(
    {
        "codigo": codigo,
        "grupo": grupo,
        "nombre": nombre,
        "descripcion": descripcion,
    }
    for grupo, permisos in PERMISOS_POR_GRUPO.items()
    for codigo, nombre, descripcion in permisos
)

TODOS_LOS_PERMISOS = frozenset(permiso["codigo"] for permiso in PERMISOS)


PERMISOS_ROLES_SISTEMA = {
    "Administrador": TODOS_LOS_PERMISOS,
    "Nivel 2": frozenset(
        codigo
        for codigo in TODOS_LOS_PERMISOS
        if not codigo.startswith(("usuarios.", "roles.", "configuracion."))
        and codigo not in {
            "facturacion.anular",
            "pacientes.eliminar",
            "licencias.configurar",
        }
    ) | {"configuracion.ver", "configuracion.editar"},
    "Registro de Facturas": frozenset(
        {
            "pacientes.ver",
            "pacientes.crear",
            "pacientes.editar",
            "facturacion.ver",
            "facturacion.crear",
            "facturacion.editar",
            "facturacion.imprimir",
            "catalogos.ver",
            "reportes.ver",
            "reportes.exportar",
            "configuracion.ver",
            "configuracion.editar",
        }
    ),
    "Oficial de servicios": frozenset(
        {
            "pacientes.ver",
            "pacientes.crear",
            "pacientes.editar",
            "turnos.ver",
            "turnos.crear",
            "turnos.llamar",
            "turnos.administrar",
            "turnos.imprimir",
            "citas.ver",
            "citas.crear",
            "citas.editar",
            "citas.cancelar",
            "catalogos.ver",
            "configuracion.ver",
            "configuracion.editar",
        }
    ),
    "Médico": frozenset(
        {
            "pacientes.ver",
            "turnos.ver",
            "turnos.llamar",
            "turnos.imprimir",
            "turnos.cola_propia",
            "historia_clinica.ver",
            "historia_clinica.crear",
            "historia_clinica.editar",
            "historia_clinica.imprimir",
            "recetas.ver",
            "recetas.crear",
            "recetas.anular",
            "recetas.imprimir",
            "licencias.ver",
            "licencias.crear",
            "licencias.editar",
            "licencias.anular",
            "licencias.imprimir",
            "emergencia.ver",
            "emergencia.crear",
            "emergencia.imprimir",
            "enfermeria.ver",
            "enfermeria.crear",
            "enfermeria.imprimir",
            "citas.ver",
            "citas.crear",
            "citas.editar",
            "catalogos.ver",
            "configuracion.ver",
            "configuracion.editar",
        }
    ),
}


DESCRIPCIONES_ROLES_SISTEMA = {
    "Administrador": "Acceso completo a la administración de la empresa.",
    "Nivel 2": "Acceso operativo amplio compatible con el perfil Nivel 2.",
    "Registro de Facturas": "Registro, consulta e impresión de facturas.",
    "Oficial de servicios": "Admisión de pacientes, citas y gestión de turnos.",
    "Médico": "Atención clínica y gestión de su propia cola.",
}


# Alias en inglés para consumidores que ya usan esa convención.
PERMISSIONS = PERMISOS
SYSTEM_ROLE_PERMISSIONS = PERMISOS_ROLES_SISTEMA


def validar_catalogo():
    """Detectar códigos repetidos o referencias inválidas al importar."""

    codigos = [permiso["codigo"] for permiso in PERMISOS]
    if len(codigos) != len(set(codigos)):
        raise ValueError("El catálogo RBAC contiene códigos de permiso repetidos")

    desconocidos = set().union(*PERMISOS_ROLES_SISTEMA.values()) - set(codigos)
    if desconocidos:
        raise ValueError(
            "Los roles RBAC hacen referencia a permisos desconocidos: "
            + ", ".join(sorted(desconocidos))
        )


validar_catalogo()
