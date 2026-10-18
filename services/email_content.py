"""Plantillas de correo transaccional (texto + HTML alineados)."""

import html

from core.presentation import PRODUCTO, SOPORTE_EMAIL_PREDETERMINADO


def _enlace_ingreso():
    """Página de entrada del sistema, para pegarla en cualquier correo."""
    from core.config import url_publica_base

    base = (url_publica_base() or 'https://www.clinicrd.com').rstrip('/')
    return f'{base}/login'


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


def _parrafos(lineas):
    return ''.join(
        f'<p style="margin:0 0 12px;line-height:1.55;color:#333;">{linea}</p>'
        for linea in lineas
    )


def _cuerpo_html(titulo, parrafos, enlace=None, etiqueta_boton=None, objetivo=''):
    partes = _parrafos(parrafos)
    aviso = ''
    if objetivo:
        aviso = (
            '<p style="margin:0 0 16px;padding:12px 14px;background:#f3fafa;'
            'border-left:3px solid #0d6e6e;color:#0d6e6e;font-size:14px;'
            f'line-height:1.45;">{html.escape(objetivo)}</p>'
        )
    accion = ''
    if enlace and etiqueta_boton:
        url = html.escape(enlace, quote=True)
        boton = html.escape(etiqueta_boton)
        accion = f'''
  <p style="margin:20px 0;">
    <a href="{url}" style="display:inline-block;padding:12px 24px;background:#0d6e6e;
       color:#fff;text-decoration:none;border-radius:8px;font-weight:600;">
      {boton}
    </a>
  </p>
  <p style="margin:0 0 8px;font-size:13px;color:#666;word-break:break-all;">
    Si el botón no abre, copie este enlace en el navegador:<br>
    <a href="{url}" style="color:#0d6e6e;">{url}</a>
  </p>'''
    return f'''
<div style="font-family:Segoe UI,Helvetica,Arial,sans-serif;max-width:560px;margin:0 auto;padding:24px;">
  <p style="margin:0 0 16px;font-size:18px;font-weight:600;color:#0d6e6e;">
    {html.escape(PRODUCTO["nombre"])}
  </p>
  <h1 style="margin:0 0 8px;font-size:20px;font-weight:600;color:#222;">
    {html.escape(titulo)}
  </h1>
  {aviso}
  {partes}
  {accion}
  {_pie_correo()}
</div>'''.strip()


def correo_activacion_demo(nombre, enlace, horas_validez=72):
    """Asunto, cuerpo texto plano y HTML para activación de demo pública."""
    saludo = (nombre or '').strip() or 'Hola'
    asunto = 'Active su demo de 7 días en ClinicRD'
    texto = (
        f'{saludo},\n\n'
        'Este correo es para activar la demo gratuita de ClinicRD que usted solicitó.\n'
        'Hasta abrir el enlace no podrá iniciar sesión.\n\n'
        'Al confirmarlo podrá usar pacientes, agenda y facturación durante 7 días.\n\n'
        f'{enlace}\n\n'
        f'El enlace vence en {horas_validez} horas y solo sirve una vez.\n'
        'Si usted no pidió esta demo, ignore el mensaje: no se creará el acceso.\n\n'
        f'Ayuda: {_reply_soporte()}\n'
        f'— {PRODUCTO["nombre"]}\n'
    )
    parrafos = [
        f'Hola {html.escape(saludo)},',
        'Registró una demo gratuita de ClinicRD. Este mensaje sirve solo para '
        '<strong>comprobar que este correo es suyo</strong> y abrir el acceso.',
        'Cuando confirme, podrá entrar durante <strong>7 días</strong> a pacientes, '
        'agenda y facturación. La contraseña que escribió en el registro será la de ingreso.',
        f'El enlace vence en {horas_validez} horas. Si no pidió esta demo, '
        'ignore el mensaje: nadie podrá entrar con él.',
    ]
    html_body = _cuerpo_html(
        'Active su demo',
        parrafos,
        enlace,
        'Activar mi demo',
        objetivo='Para entrar la primera vez. Sin este paso la cuenta queda bloqueada.',
    )
    return asunto, texto, html_body


def correo_invitacion_usuario(nombre, enlace, horas_validez=72):
    """Asunto, texto y HTML para invitación de usuario en un consultorio."""
    saludo = (nombre or '').strip() or 'Hola'
    asunto = 'Le crearon un usuario en ClinicRD: actívelo'
    texto = (
        f'{saludo},\n\n'
        'Su consultorio le creó un usuario en ClinicRD.\n'
        'Este correo confirma que la dirección es suya y le permite entrar la primera vez.\n\n'
        'Abra el enlace, defina su contraseña personal y luego inicie sesión.\n'
        f'{enlace}\n\n'
        f'Vence en {horas_validez} horas. Si no esperaba este usuario, ignore el mensaje.\n\n'
        f'Ayuda: {_reply_soporte()}\n'
        f'— {PRODUCTO["nombre"]}\n'
    )
    parrafos = [
        f'Hola {html.escape(saludo)},',
        'El administrador de su consultorio creó un usuario a su nombre. '
        'Este mensaje no es una factura ni un aviso clínico: sirve para '
        '<strong>validar su correo y elegir su clave</strong>.',
        'Después de activar, entre con este mismo correo. '
        f'El enlace vence en {horas_validez} horas y no debe reenviarlo.',
        'Si usted no trabaja en ese consultorio, ignore el mensaje. '
        'La cuenta no se activará.',
    ]
    html_body = _cuerpo_html(
        'Active su usuario',
        parrafos,
        enlace,
        'Activar mi usuario',
        objetivo='Primer acceso. Hasta abrir el enlace no podrá iniciar sesión.',
    )
    return asunto, texto, html_body


def correo_cambio_email_empresa(nombre_empresa, enlace, horas_validez=48):
    """Confirmación antes de reemplazar el correo de la empresa."""
    empresa = (nombre_empresa or 'su empresa').strip()
    asunto = f'Confirme el correo nuevo de {empresa}'
    texto = (
        f'Solicitaron guardar este buzón como correo de {empresa} en ClinicRD.\n\n'
        'El correo anterior sigue vigente hasta que usted confirme aquí:\n'
        f'{enlace}\n\n'
        f'El enlace vence en {horas_validez} horas.\n'
        'Si no pidió el cambio, no abra el enlace: no se reemplazará nada.\n\n'
        f'Ayuda: {_reply_soporte()}\n'
        f'— {PRODUCTO["nombre"]}\n'
    )
    parrafos = [
        f'Alguien editó los datos de <strong>{html.escape(empresa)}</strong> '
        'y escribió esta dirección como correo de la empresa.',
        'Este mensaje pide confirmar que el buzón es correcto. '
        'Facturas, avisos y contacto de ClinicRD seguirán yendo al correo anterior '
        'hasta que pulse el botón.',
        f'El enlace vence en {horas_validez} horas. '
        'Si no reconoce la solicitud, ignórela.',
    ]
    html_body = _cuerpo_html(
        'Confirme este correo',
        parrafos,
        enlace,
        'Sí, usar este correo',
        objetivo='Solo cambia el correo de la empresa. No cambia contraseñas ni usuarios.',
    )
    return asunto, texto, html_body


def correo_clave_temporal(nombre, clave, email=None):
    """El administrador generó una clave: el correo la trae, con el enlace para entrar."""
    saludo = (nombre or '').strip() or 'Hola'
    clave_visible = (clave or '').strip()
    correo = (email or '').strip()
    ingreso = _enlace_ingreso()
    cuenta = f'Correo de la cuenta: {correo}\n' if correo else ''
    asunto = 'Su contraseña temporal de ClinicRD'
    texto = (
        f'{saludo},\n\n'
        'Un administrador generó una contraseña temporal para su usuario ClinicRD.\n'
        'La contraseña anterior ya no sirve.\n\n'
        f'Entre aquí: {ingreso}\n'
        f'{cuenta}'
        f'Contraseña temporal: {clave_visible}\n\n'
        'Al entrar, el sistema le pedirá crear una propia antes de poder trabajar. '
        'No comparta este correo.\n\n'
        f'Ayuda: {_reply_soporte()}\n'
        f'— {PRODUCTO["nombre"]}\n'
    )
    clave_html = html.escape(clave_visible)
    parrafos = [
        f'Hola {html.escape(saludo)},',
        'Un administrador generó una contraseña temporal porque no podía entrar. '
        'La contraseña anterior ya no sirve.',
        (
            f'Entre con el correo <strong>{html.escape(correo)}</strong>.'
            if correo else
            'Entre con el correo de su cuenta.'
        ),
        'Use esta clave:',
        (
            '<span style="display:inline-block;padding:10px 14px;background:#f4f7f8;'
            'border:1px dashed #0d6e6e;border-radius:8px;font-family:Consolas,monospace;'
            f'font-size:18px;letter-spacing:0.04em;">{clave_html}</span>'
        ),
        'Al entrar, ClinicRD le obliga a cambiarla por una contraseña suya. '
        'Hasta ese cambio no puede operar. No reenvíe este correo.',
    ]
    html_body = _cuerpo_html(
        'Entre con esta clave temporal',
        parrafos,
        enlace=ingreso,
        etiqueta_boton='Entrar a ClinicRD',
        objetivo='El primer inicio de sesión le pedirá crear una contraseña nueva.',
    )
    return asunto, texto, html_body


def correo_cambio_password(nombre, enlace, horas_validez=48, bloquea_actual=False):
    """Confirmación antes de reemplazar la contraseña."""
    saludo = (nombre or '').strip() or 'Hola'
    asunto = 'Confirme el cambio de su contraseña'
    if bloquea_actual:
        texto = (
            f'{saludo},\n\n'
            'Un administrador cambió la contraseña de su usuario ClinicRD.\n'
            'La clave anterior ya no sirve. Para entrar debe abrir este enlace '
            'y confirmar la nueva.\n\n'
            f'{enlace}\n\n'
            f'El enlace vence en {horas_validez} horas y es de un solo uso.\n'
            'No comparta este correo. Si usted no reconoce el cambio, avise a soporte.\n\n'
            f'Ayuda: {_reply_soporte()}\n'
            f'— {PRODUCTO["nombre"]}\n'
        )
        parrafos = [
            f'Hola {html.escape(saludo)},',
            'Un administrador guardó una contraseña nueva para su usuario. '
            'Este mensaje no trae esa clave.',
            'La contraseña anterior ya no permite entrar. '
            'Abra el enlace para activar la nueva y úsela en el próximo inicio de sesión.',
            f'El enlace vence en {horas_validez} horas. '
            'Si no reconoce el cambio, no lo abra y avise a soporte.',
        ]
        objetivo = (
            'La clave anterior quedó bloqueada. '
            'Solo el enlace activa la contraseña nueva.'
        )
    else:
        texto = (
            f'{saludo},\n\n'
            'Se pidió reemplazar la contraseña de su usuario ClinicRD.\n'
            'La clave con la que entra hoy sigue funcionando hasta que confirme.\n\n'
            f'{enlace}\n\n'
            f'El enlace vence en {horas_validez} horas y es de un solo uso.\n'
            'No comparta este correo. Si usted no pidió el cambio, ignórelo.\n\n'
            f'Ayuda: {_reply_soporte()}\n'
            f'— {PRODUCTO["nombre"]}\n'
        )
        parrafos = [
            f'Hola {html.escape(saludo)},',
            'Este mensaje no contiene su contraseña. Sirve para autorizar '
            'el reemplazo que se guardó como pendiente en ClinicRD.',
            'Si confirma, la próxima vez deberá entrar con la clave nueva. '
            'Si no confirma, seguirá usando la actual.',
            f'El enlace vence en {horas_validez} horas. '
            'Si no reconoce la solicitud, no lo abra y avise a soporte.',
        ]
        objetivo = 'Su contraseña actual no cambia hasta que abra este enlace.'
    html_body = _cuerpo_html(
        'Autorice la clave nueva',
        parrafos,
        enlace,
        'Confirmar la contraseña nueva',
        objetivo=objetivo,
    )
    return asunto, texto, html_body


def correo_recuperar_password(nombre, enlace, horas_validez=1):
    """Olvidé mi contraseña: el enlace crea una clave nueva, no revela la anterior."""
    saludo = (nombre or '').strip() or 'Hola'
    asunto = 'Cree una contraseña nueva para ClinicRD'
    texto = (
        f'{saludo},\n\n'
        'Alguien pidió restablecer la contraseña de su usuario ClinicRD.\n'
        'No podemos ver ni enviar la clave anterior. Con este enlace usted crea una nueva.\n\n'
        '1. Abra el enlace.\n'
        '2. Escriba una contraseña de al menos 8 caracteres, con mayúscula, '
        'minúscula y número.\n'
        '3. Inicie sesión con esa clave.\n\n'
        f'{enlace}\n\n'
        f'El enlace vence en {horas_validez} hora y solo funciona una vez.\n'
        'Hasta terminar esos pasos, su contraseña actual sigue igual.\n'
        'Si usted no lo pidió, ignore este mensaje.\n\n'
        f'Ayuda: {_reply_soporte()}\n'
        f'— {PRODUCTO["nombre"]}\n'
    )
    parrafos = [
        f'Hola {html.escape(saludo)},',
        'Recibimos una solicitud de <strong>olvidé mi contraseña</strong> '
        'para este correo. ClinicRD no envía la clave que ya tiene: '
        'este paso le deja escribir una nueva.',
        'Al abrir el botón podrá definirla y, enseguida, iniciar sesión. '
        'Use al menos 8 caracteres, una mayúscula, una minúscula y un número.',
        f'El enlace vence en {horas_validez} hora y no debe reenviarlo. '
        'Si usted no pidió el cambio, ignore el correo: su clave actual no se toca.',
    ]
    html_body = _cuerpo_html(
        'Restablezca su contraseña',
        parrafos,
        enlace,
        'Crear una contraseña nueva',
        objetivo='Solo sirve si olvidó su clave. No es un aviso de que ya fue cambiada.',
    )
    return asunto, texto, html_body


def correo_factura_suscripcion(empresa, numero, periodo, monto):
    """Cobro de ClinicRD a la empresa cliente."""
    nombre = empresa or 'su empresa'
    asunto = f'Factura {numero} de su suscripción ClinicRD'
    texto = (
        f'Adjuntamos la factura {numero} de la suscripción ClinicRD de {nombre}.\n\n'
        f'Periodo: {periodo}\n'
        f'Monto: RD$ {monto}\n\n'
        'El PDF viene con este mensaje. No incluye datos clínicos de pacientes.\n'
        f'Para pagar o aclarar el cobro escriba a {_reply_soporte()}.\n'
    )
    parrafos = [
        f'Le enviamos la factura de suscripción de <strong>{html.escape(nombre)}</strong>.',
        f'<strong>Número:</strong> {html.escape(str(numero))}<br>'
        f'<strong>Periodo:</strong> {html.escape(str(periodo))}<br>'
        f'<strong>Monto:</strong> RD$ {html.escape(str(monto))}',
        'El detalle está en el PDF adjunto. Este correo es el cobro del software, '
        'no una factura de pacientes ni de una ARS.',
        f'Si el monto o el periodo no coinciden, responda a {_reply_soporte()}.',
    ]
    return asunto, texto, _cuerpo_html(
        'Factura de suscripción',
        parrafos,
        objetivo='Cobro de ClinicRD por el uso del sistema.',
    )


def correo_factura_clinica(numero, fecha, ncf, total, consultorio):
    """Factura clínica enviada al paciente o a la ARS."""
    lugar = consultorio or 'su consultorio'
    asunto = f'Factura {numero} de {lugar}'
    texto = (
        f'{lugar} le envía la factura {numero}.\n\n'
        f'Fecha: {fecha}\n'
        f'NCF: {ncf or "—"}\n'
        f'Total: RD$ {total}\n\n'
        'El PDF va adjunto. Consérvelo para su reclamo o sus registros.\n'
    )
    parrafos = [
        f'<strong>{html.escape(lugar)}</strong> le envía este comprobante.',
        f'<strong>Factura:</strong> {html.escape(str(numero))}<br>'
        f'<strong>Fecha:</strong> {html.escape(str(fecha))}<br>'
        f'<strong>NCF:</strong> {html.escape(str(ncf or "—"))}<br>'
        f'<strong>Total:</strong> RD$ {html.escape(str(total))}',
        'Abra el PDF adjunto para ver el detalle. '
        'Guárdelo si debe presentarlo a su seguro o a la ARS.',
    ]
    return asunto, texto, _cuerpo_html(
        'Su factura',
        parrafos,
        objetivo='Comprobante de la atención. No cambia citas ni contraseñas.',
    )


def correo_cita(fecha, hora, tipo='programada', enlace=None):
    """Aviso al paciente: cita nueva, cambio de fecha o recordatorio."""
    cuando = f'{fecha} a las {hora}'
    if tipo == 'reagendada':
        asunto = f'Su cita cambió: {cuando}'
        objetivo = 'El consultorio movió su cita. Confirme si puede asistir en el horario nuevo.'
        intro = (
            f'Su cita <strong>cambió</strong> y quedó para el '
            f'<strong>{html.escape(str(fecha))}</strong> a las '
            f'<strong>{html.escape(str(hora))}</strong>.'
        )
        texto_intro = f'Su cita cambió y quedó para el {cuando}.'
    elif tipo == 'recordatorio':
        asunto = f'Recordatorio: cita el {cuando}'
        objetivo = 'Recordatorio de una cita que ya tiene. No es una cita nueva.'
        intro = (
            f'Le recordamos su cita del <strong>{html.escape(str(fecha))}</strong> '
            f'a las <strong>{html.escape(str(hora))}</strong>.'
        )
        texto_intro = f'Le recordamos su cita del {cuando}.'
    else:
        asunto = f'Cita agendada para el {cuando}'
        objetivo = 'El consultorio le apartó esta cita. Confirme o cancélela sin llamar.'
        intro = (
            f'Le agendaron una cita para el <strong>{html.escape(str(fecha))}</strong> '
            f'a las <strong>{html.escape(str(hora))}</strong>.'
        )
        texto_intro = f'Le agendaron una cita para el {cuando}.'
    texto = (
        f'{texto_intro}\n\n'
        'Este correo es solo sobre su cita. No incluye resultados ni facturas.\n'
    )
    parrafos = [
        intro,
        'Llegue unos minutos antes y lleve su cédula y el carné del seguro, si aplica.',
    ]
    if enlace:
        texto += (
            'Para confirmar que asistirá, o para cancelar, abra:\n'
            f'{enlace}\n'
        )
        parrafos.append(
            'Use el botón para decir si asistirá o si necesita cancelar. '
            'No hace falta llamar al consultorio.'
        )
    else:
        parrafos.append(
            'Si no puede asistir, llame al consultorio para reprogramar.'
        )
    return asunto, texto, _cuerpo_html(
        'Su cita',
        parrafos,
        enlace,
        'Confirmar o cancelar' if enlace else None,
        objetivo=objetivo,
    )


def correo_receta():
    """Aviso de que el médico emitió una receta. El detalle no viaja en el correo."""
    asunto = 'El médico emitió su receta'
    texto = (
        'Su médico emitió una receta a su nombre.\n\n'
        'Este correo solo avisa. Los medicamentos y las indicaciones '
        'se las entrega el consultorio en papel o en el sistema.\n'
        'No responda a este mensaje con datos clínicos.\n'
    )
    parrafos = [
        'Su médico dejó emitida una receta médica a su nombre.',
        'Por privacidad, este correo <strong>no incluye</strong> los medicamentos '
        'ni el diagnóstico. Pida el detalle en el consultorio o al retirar la receta impresa.',
        'Si usted no tuvo consulta, ignore el mensaje y avise al consultorio.',
    ]
    return asunto, texto, _cuerpo_html(
        'Receta lista',
        parrafos,
        objetivo='Aviso de receta. No sustituye la receta impresa ni cambia su cita.',
    )


def correo_aviso_correo_empresa(nombre_empresa, correo_nuevo):
    """Aviso al buzón que sigue vigente mientras el nuevo no se confirma."""
    empresa = nombre_empresa or 'la empresa'
    asunto = f'Aviso: quieren cambiar el correo de {empresa}'
    texto = (
        f'Se pidió cambiar el correo de {empresa} a {correo_nuevo}.\n\n'
        'Este buzón sigue siendo el oficial hasta que la dirección nueva '
        'confirme el enlace que le enviamos.\n'
        'Usted no tiene que hacer nada si el cambio es correcto.\n'
        'Si no lo reconoce, entre a ClinicRD y deje el correo anterior.\n'
    )
    parrafos = [
        f'Se solicitó que el correo de <strong>{html.escape(empresa)}</strong> '
        f'pase a ser {html.escape(correo_nuevo)}.',
        'Le escribimos a esta dirección porque <strong>todavía es la vigente</strong>. '
        'El cambio solo ocurre si la otra dirección abre su enlace de confirmación.',
        'No necesita responder si usted pidió el cambio. '
        'Si no lo pidió, conserve este correo y avise a soporte antes de que confirmen.',
    ]
    return asunto, texto, _cuerpo_html(
        'Su correo sigue activo',
        parrafos,
        objetivo='Aviso de seguridad. Este mensaje no confirma el cambio.',
    )
