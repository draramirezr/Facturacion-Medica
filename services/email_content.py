"""Plantillas de correo transaccional (texto + HTML alineados)."""

import html

from core.presentation import PRODUCTO, SOPORTE_EMAIL_PREDETERMINADO


def _reply_soporte():
    import os
    return (
        os.getenv('SOPORTE_EMAIL', '').strip()
        or SOPORTE_EMAIL_PREDETERMINADO
    )


def _pie_correo():
    soporte = html.escape(_reply_soporte())
    return (
        f'<p style="margin:24px 0 0;font-size:13px;color:#666;">'
        f'¿Necesita ayuda? Escríbanos a '
        f'<a href="mailto:{soporte}">{soporte}</a>.</p>'
        f'<p style="margin:8px 0 0;font-size:12px;color:#999;">'
        f'{html.escape(PRODUCTO["nombre"])} · Gestión para consultorios y centros de salud'
        f'</p>'
    )


def _cuerpo_html(titulo, parrafos, enlace, etiqueta_boton):
    partes = ''.join(
        f'<p style="margin:0 0 12px;line-height:1.5;color:#333;">{p}</p>'
        for p in parrafos
    )
    url = html.escape(enlace, quote=True)
    boton = html.escape(etiqueta_boton)
    return f'''
<div style="font-family:Segoe UI,Helvetica,Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;">
  <p style="margin:0 0 16px;font-size:18px;font-weight:600;color:#0d6e6e;">
    {html.escape(PRODUCTO["nombre"])}
  </p>
  <h1 style="margin:0 0 16px;font-size:20px;font-weight:600;color:#222;">
    {html.escape(titulo)}
  </h1>
  {partes}
  <p style="margin:20px 0;">
    <a href="{url}" style="display:inline-block;padding:12px 24px;background:#0d6e6e;
       color:#fff;text-decoration:none;border-radius:8px;font-weight:600;">
      {boton}
    </a>
  </p>
  <p style="margin:0 0 8px;font-size:13px;color:#666;word-break:break-all;">
    Si el botón no funciona, copie este enlace en el navegador:<br>
    <a href="{url}" style="color:#0d6e6e;">{url}</a>
  </p>
  {_pie_correo()}
</div>'''.strip()


def correo_activacion_demo(nombre, enlace, horas_validez=72):
    """Asunto, cuerpo texto plano y HTML para activación de demo pública."""
    saludo = (nombre or '').strip() or 'Hola'
    asunto = 'Confirme su correo para activar ClinicRD'
    texto = (
        f'{saludo},\n\n'
        'Recibimos su solicitud para probar ClinicRD (demo gratuita de 7 días).\n\n'
        'Para validar su correo y crear su acceso, abra este enlace:\n'
        f'{enlace}\n\n'
        f'El enlace vence en {horas_validez} horas.\n\n'
        'Si usted no solicitó esta cuenta, puede ignorar este mensaje.\n\n'
        f'Ayuda: {_reply_soporte()}\n'
        f'— {PRODUCTO["nombre"]}\n'
    )
    parrafos = [
        f'Hola {html.escape(saludo)},',
        'Recibimos su solicitud para probar ClinicRD (demo gratuita de 7 días). '
        'Para <strong>validar su correo</strong> y entrar la primera vez, use el botón:',
        f'El enlace vence en {horas_validez} horas. Si no solicitó esta demo, '
        'ignore este mensaje.',
    ]
    html_body = _cuerpo_html(
        'Confirme su correo',
        parrafos,
        enlace,
        'Activar mi cuenta',
    )
    return asunto, texto, html_body


def correo_invitacion_usuario(nombre, enlace, horas_validez=72):
    """Asunto, texto y HTML para invitación de usuario en un consultorio."""
    saludo = (nombre or '').strip() or 'Hola'
    asunto = 'Active su cuenta de ClinicRD'
    texto = (
        f'{saludo},\n\n'
        'Le crearon un usuario en ClinicRD.\n\n'
        'Para validar su correo y entrar la primera vez, abra:\n'
        f'{enlace}\n\n'
        f'El enlace vence en {horas_validez} horas.\n\n'
        'Si no esperaba este mensaje, ignórelo.\n\n'
        f'Ayuda: {_reply_soporte()}\n'
        f'— {PRODUCTO["nombre"]}\n'
    )
    parrafos = [
        f'Hola {html.escape(saludo)},',
        'Le crearon un usuario en ClinicRD. Para validar su correo y '
        'definir su contraseña, use el botón:',
        f'El enlace vence en {horas_validez} horas.',
    ]
    html_body = _cuerpo_html(
        'Active su cuenta',
        parrafos,
        enlace,
        'Activar mi cuenta',
    )
    return asunto, texto, html_body
