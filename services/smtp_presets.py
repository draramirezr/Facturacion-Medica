"""Plantillas SMTP y validación del formulario de correo del consultorio."""

from routes.support import validate_email

SMTP_PRESETS = {
    'gmail': {
        'etiqueta': 'Gmail',
        'smtp_host': 'smtp.gmail.com',
        'smtp_port': 587,
        'smtp_usar_tls': True,
        'ayuda': (
            'Verificación en 2 pasos activa y contraseña de aplicación '
            'de 16 caracteres (no la clave normal).'
        ),
    },
    'outlook': {
        'etiqueta': 'Outlook / Hotmail',
        'smtp_host': 'smtp-mail.outlook.com',
        'smtp_port': 587,
        'smtp_usar_tls': True,
        'ayuda': (
            'Use la misma cuenta en Usuario y Remitente. Si falla el login, '
            'Microsoft puede exigir contraseña de aplicación o bloquear SMTP '
            'en cuentas personales; pruebe Microsoft 365 de su dominio.'
        ),
    },
    'office365': {
        'etiqueta': 'Microsoft 365',
        'smtp_host': 'smtp.office365.com',
        'smtp_port': 587,
        'smtp_usar_tls': True,
        'ayuda': 'Correo corporativo @su-dominio.com y contraseña de la cuenta o de aplicación.',
    },
    'hostinger': {
        'etiqueta': 'Hostinger',
        'smtp_host': 'smtp.hostinger.com',
        'smtp_port': 587,
        'smtp_usar_tls': True,
        'ayuda': 'Usuario suele ser el correo completo creado en el hosting.',
    },
}


def sugerir_preset_por_remitente(correo):
    """Inferir plantilla a partir del dominio del remitente."""
    texto = (correo or '').strip().lower()
    if not validate_email(texto):
        return None
    dominio = texto.split('@', 1)[-1]
    if dominio in ('gmail.com', 'googlemail.com'):
        return 'gmail'
    if dominio in (
        'hotmail.com', 'outlook.com', 'live.com',
        'hotmail.es', 'outlook.es', 'live.com.mx',
    ):
        return 'outlook'
    return None


def estado_configuracion_smtp(resumen):
    """Texto corto de lo que falta para poder enviar."""
    resumen = resumen or {}
    faltantes = []
    if not (resumen.get('smtp_host') or '').strip():
        faltantes.append('servidor SMTP')
    if not (resumen.get('smtp_remitente') or '').strip():
        faltantes.append('correo remitente')
    if not resumen.get('tiene_password'):
        faltantes.append('contraseña SMTP')
    listo = not faltantes
    return {
        'listo_para_enviar': listo,
        'faltantes': faltantes,
    }


def validar_formulario_smtp(
    host,
    remitente,
    password_nueva,
    tiene_password_guardada,
    enviar_prueba=False,
):
    """None si OK; mensaje de error legible si no."""
    host = (host or '').strip()
    remitente = (remitente or '').strip()
    if remitente and not validate_email(remitente):
        return 'El correo remitente no es válido.'
    if enviar_prueba:
        if not host:
            return (
                'Indique el servidor SMTP. Use una plantilla (Gmail u Outlook) '
                'si no conoce el host.'
            )
        if not remitente:
            return 'Indique el correo remitente (debe coincidir con su cuenta SMTP).'
        if not password_nueva and not tiene_password_guardada:
            return (
                'Indique la contraseña SMTP. En Gmail use contraseña de '
                'aplicación de 16 caracteres.'
            )
        return None
    if host and not remitente:
        return 'Si configura el servidor SMTP, indique también el correo remitente.'
    if remitente and not host:
        return (
            'Falta el servidor SMTP. Elija Gmail, Outlook u otra plantilla, '
            'o escriba smtp.sudominio.com.'
        )
    if (host or remitente) and not password_nueva and not tiene_password_guardada:
        return (
            'Guarde también la contraseña SMTP (obligatoria la primera vez).'
        )
    return None
