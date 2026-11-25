"""Rutas del dominio de facturación.

El código vive en los módulos routes/billing_*.py; aquí solo se registran
las URLs (endpoints legacy sin blueprint).
"""
from routes.billing_common import (
    facturacion_menu,
)
from routes.billing_claims import (
    facturacion_reclamacion_cambiar_estado,
    facturacion_reclamacion_detalle,
    facturacion_reclamacion_editar,
    facturacion_reclamaciones,
    facturacion_reclamaciones_nueva,
)
from routes.billing_payments import (
    facturacion_pago_detalle,
    facturacion_pago_editar,
    facturacion_pagos,
    facturacion_pagos_nuevo,
)
from routes.billing_invoice_view import (
    facturacion_consultar_estado_ecf,
    facturacion_dgii_certificado,
    facturacion_historico,
    facturacion_qr_ecf,
    facturacion_representacion_impresa_ecf,
    facturacion_ver_factura,
    facturacion_ver_xml_ecf,
)
from routes.billing_invoice_edit import (
    facturacion_anular_factura,
    facturacion_editar_factura,
)
from routes.billing_invoice_pdf import (
    facturacion_descargar_pdf,
    facturacion_enviar_email,
)
from routes.billing_dashboard import (
    facturacion_dashboard,
)
from routes.billing_pending import (
    descargar_plantilla_excel,
    facturacion_facturas_nueva,
    facturacion_procesar_excel,
)
from routes.billing_generate import (
    facturacion_generar,
    facturacion_generar_final,
    facturacion_generar_step2,
    facturacion_vista_previa,
)


def register_billing_routes(app):
    """Registrar facturación conservando endpoints legacy."""
    app.add_url_rule('/facturacion', endpoint='facturacion_menu', view_func=facturacion_menu)
    app.add_url_rule('/facturacion/reclamaciones', endpoint='facturacion_reclamaciones', view_func=facturacion_reclamaciones)
    app.add_url_rule('/facturacion/reclamaciones/nueva', endpoint='facturacion_reclamaciones_nueva', view_func=facturacion_reclamaciones_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/reclamaciones/<int:reclamacion_id>', endpoint='facturacion_reclamacion_detalle', view_func=facturacion_reclamacion_detalle)
    app.add_url_rule('/facturacion/reclamaciones/<int:reclamacion_id>/editar', endpoint='facturacion_reclamacion_editar', view_func=facturacion_reclamacion_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/reclamaciones/<int:reclamacion_id>/estado', endpoint='facturacion_reclamacion_cambiar_estado', view_func=facturacion_reclamacion_cambiar_estado, methods=['POST'])
    app.add_url_rule('/facturacion/pagos', endpoint='facturacion_pagos', view_func=facturacion_pagos)
    app.add_url_rule('/facturacion/pagos/nuevo', endpoint='facturacion_pagos_nuevo', view_func=facturacion_pagos_nuevo, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/pagos/<int:pago_id>', endpoint='facturacion_pago_detalle', view_func=facturacion_pago_detalle)
    app.add_url_rule('/facturacion/pagos/<int:pago_id>/editar', endpoint='facturacion_pago_editar', view_func=facturacion_pago_editar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/historico', endpoint='facturacion_historico', view_func=facturacion_historico)
    app.add_url_rule(
        '/facturacion/dgii/certificado',
        endpoint='facturacion_dgii_certificado',
        view_func=facturacion_dgii_certificado,
        methods=['GET', 'POST'],
    )
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/ver', endpoint='facturacion_ver_factura', view_func=facturacion_ver_factura)
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/ecf/xml', endpoint='facturacion_ver_xml_ecf', view_func=facturacion_ver_xml_ecf)
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/ecf/qr', endpoint='facturacion_qr_ecf', view_func=facturacion_qr_ecf)
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/ecf/representacion-impresa', endpoint='facturacion_representacion_impresa_ecf', view_func=facturacion_representacion_impresa_ecf)
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/ecf/consultar-estado', endpoint='facturacion_consultar_estado_ecf', view_func=facturacion_consultar_estado_ecf, methods=['POST'])
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/editar', endpoint='facturacion_editar_factura', view_func=facturacion_editar_factura, methods=['GET', 'POST'])
    app.add_url_rule(
        '/facturacion/facturas/<int:factura_id>/anular',
        endpoint='facturacion_anular_factura',
        view_func=facturacion_anular_factura,
        methods=['POST'],
    )
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/pdf', endpoint='facturacion_descargar_pdf', view_func=facturacion_descargar_pdf)
    app.add_url_rule('/facturacion/facturas/<int:factura_id>/enviar-email', endpoint='facturacion_enviar_email', view_func=facturacion_enviar_email, methods=['POST'])
    app.add_url_rule('/facturacion/dashboard', endpoint='facturacion_dashboard', view_func=facturacion_dashboard)
    app.add_url_rule('/facturacion/facturas/nueva', endpoint='facturacion_facturas_nueva', view_func=facturacion_facturas_nueva, methods=['GET', 'POST'])
    app.add_url_rule('/descargar-plantilla-excel', endpoint='descargar_plantilla_excel', view_func=descargar_plantilla_excel)
    app.add_url_rule('/facturacion/procesar-excel', endpoint='facturacion_procesar_excel', view_func=facturacion_procesar_excel, methods=['POST'])
    app.add_url_rule('/facturacion/generar', endpoint='facturacion_generar', view_func=facturacion_generar, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/generar/step2', endpoint='facturacion_generar_step2', view_func=facturacion_generar_step2, methods=['GET', 'POST'])
    app.add_url_rule('/facturacion/vista-previa', endpoint='facturacion_vista_previa', view_func=facturacion_vista_previa)
    app.add_url_rule('/facturacion/generar/final', endpoint='facturacion_generar_final', view_func=facturacion_generar_final, methods=['POST'])
