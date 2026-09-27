"""Catálogo de pruebas de laboratorio para buscar al escribir la orden."""

import logging
import re

from core.database import execute_query, execute_update

logger = logging.getLogger(__name__)

# Nombre visible, texto de búsqueda (sinónimos).
PRUEBAS_BASE = (
    ('Hemograma completo', 'cbc sangre completa hematocrito hemoglobina leucocitos'),
    ('Hemoglobina', 'hb anemia'),
    ('Hematocrito', 'hto hct'),
    ('Recuento de plaquetas', 'plaqueta trombocitos'),
    ('VSG', 'eritrosedimentacion sedimentacion'),
    ('PCR', 'proteina c reactiva inflamacion'),
    ('Glicemia en ayunas', 'glucosa azucar diabetes'),
    ('Glicemia al azar', 'glucosa'),
    ('Hemoglobina glicosilada (HbA1c)', 'hba1c glicosilada diabetes'),
    ('Curva de tolerancia a la glucosa', 'ptgo diabetes gestacional'),
    ('Insulina', 'resistencia insulina'),
    ('Urea', 'bun nitrogeno'),
    ('Creatinina', 'renal rinon'),
    ('Ácido úrico', 'gota urico'),
    ('AST (TGO)', 'higado transaminasa'),
    ('ALT (TGP)', 'higado transaminasa'),
    ('GGT', 'higado'),
    ('Fosfatasa alcalina', 'fal higado hueso'),
    ('Bilirrubina total', 'higado ictericia'),
    ('Bilirrubina directa', 'higado'),
    ('Proteínas totales', 'higado nutricion'),
    ('Albúmina', 'higado'),
    ('Perfil lipídico', 'colesterol trigliceridos hdl ldl'),
    ('Colesterol total', 'lipidos'),
    ('HDL', 'colesterol bueno'),
    ('LDL', 'colesterol malo'),
    ('Triglicéridos', 'lipidos'),
    ('TSH', 'tiroides'),
    ('T3', 'tiroides'),
    ('T4', 'tiroides'),
    ('T4 libre', 'tiroides'),
    ('Anti-TPO', 'tiroides hashimoto'),
    ('PSA total', 'prostata'),
    ('PSA libre', 'prostata'),
    ('Beta HCG cuantitativa', 'embarazo hormona'),
    ('Examen general de orina', 'ego orina uroanalisis'),
    ('Urocultivo', 'orina infeccion itu'),
    ('Coprológico', 'heces heces'),
    ('Coprocultivo', 'heces diarrea'),
    ('Sangre oculta en heces', 'soh colon'),
    ('Prueba de embarazo en orina', 'hcg orina'),
    ('VIH', 'sida elisa antigeno'),
    ('VDRL', 'sifilis'),
    ('HBsAg', 'hepatitis b'),
    ('Anti-HCV', 'hepatitis c'),
    ('Grupo sanguíneo y RH', 'abo rh tipo sangre'),
    ('TP (tiempo de protrombina)', 'coagulacion inr'),
    ('TPT', 'coagulacion ptt'),
    ('INR', 'coagulacion warfarina'),
    ('Ferritina', 'hierro anemia'),
    ('Hierro sérico', 'anemia'),
    ('Vitamina D', '25 oh'),
    ('Vitamina B12', 'cobalamina'),
    ('Ácido fólico', 'folato'),
    ('Sodio', 'electrolitos na'),
    ('Potasio', 'electrolitos k'),
    ('Cloro', 'electrolitos'),
    ('Magnesio', 'mg'),
    ('Calcio', 'hueso'),
    ('Fósforo', 'hueso'),
    ('Amilasa', 'pancreas'),
    ('Lipasa', 'pancreas'),
    ('Troponina', 'infarto corazon'),
    ('CK-MB', 'corazon'),
    ('Dímero D', 'trombo coagulation'),
    ('COVID-19 antígeno', 'coronavirus'),
    ('COVID-19 PCR', 'coronavirus'),
    ('Influenza A/B', 'gripe'),
    ('Dengue NS1', 'dengue'),
    ('Dengue IgM/IgG', 'dengue'),
    ('Gota gruesa', 'malaria paludismo'),
    ('Helicobacter pylori (heces o aliento)', 'ulcera gastritis'),
    ('ANA', 'lupus autoinmune'),
    ('Factor reumatoide', 'artritis'),
    ('ASO', 'estreptococo'),
    ('IgE total', 'alergia'),
    ('Cultivo faríngeo', 'garganta estreptococo'),
    ('Papanicolaou', 'pap cuello uterino'),
    ('HPV', 'papiloma'),
    ('Prolactina', 'hormona'),
    ('FSH', 'hormona fertilidad'),
    ('LH', 'hormona'),
    ('Estradiol', 'hormona'),
    ('Testosterona', 'hormona'),
    ('Cortisol', 'suprarrenal'),
)


def _normalizar_busqueda(texto):
    texto = (texto or '').casefold()
    return re.sub(r'\s+', ' ', texto).strip()


def asegurar_catalogo_laboratorios():
    execute_update(
        '''
        CREATE TABLE IF NOT EXISTS catalogo_pruebas_laboratorio (
            id INT AUTO_INCREMENT PRIMARY KEY,
            tenant_id INT NOT NULL DEFAULT 0,
            nombre VARCHAR(160) NOT NULL,
            busqueda VARCHAR(255) NOT NULL DEFAULT '',
            activo TINYINT(1) NOT NULL DEFAULT 1,
            UNIQUE KEY uq_lab_nombre (tenant_id, nombre)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        '''
    )
    existentes = execute_query(
        'SELECT COUNT(*) AS n FROM catalogo_pruebas_laboratorio WHERE tenant_id=0',
    ) or {}
    if (existentes.get('n') or 0) > 0:
        return
    for nombre, extra in PRUEBAS_BASE:
        busqueda = _normalizar_busqueda(f'{nombre} {extra}')
        execute_update(
            '''
            INSERT IGNORE INTO catalogo_pruebas_laboratorio
                (tenant_id, nombre, busqueda, activo)
            VALUES (0, %s, %s, 1)
            ''',
            (nombre, busqueda),
        )


def coincidencias_catalogo(termino, limite=20):
    """Búsqueda sobre el listado base (sin BD), para pruebas y respaldo."""
    termino = _normalizar_busqueda(termino)[:80]
    termino = re.sub(r'[%_\\]', '', termino)
    if len(termino) < 1:
        return []
    hallados = []
    for nombre, extra in PRUEBAS_BASE:
        haystack = _normalizar_busqueda(f'{nombre} {extra}')
        if termino in haystack:
            hallados.append(nombre)
        if len(hallados) >= limite:
            break
    return hallados


def buscar_pruebas_laboratorio(termino, tenant_id, limite=20):
    asegurar_catalogo_laboratorios()
    termino = _normalizar_busqueda(termino)[:80]
    termino = re.sub(r'[%_\\]', '', termino)
    if len(termino) < 1:
        return []
    patron = f'%{termino}%'
    filas = execute_query(
        '''
        SELECT nombre
        FROM catalogo_pruebas_laboratorio
        WHERE activo=1
          AND (tenant_id=0 OR tenant_id=%s)
          AND (nombre LIKE %s OR busqueda LIKE %s)
        ORDER BY CHAR_LENGTH(nombre) ASC, nombre ASC
        LIMIT %s
        ''',
        (int(tenant_id or 0), patron, patron, int(limite)),
        fetch='all',
    )
    if filas is None:
        return coincidencias_catalogo(termino, limite)
    filas = filas or []
    vistos = set()
    resultado = []
    for fila in filas:
        nombre = (fila.get('nombre') or '').strip()
        clave = nombre.casefold()
        if not nombre or clave in vistos:
            continue
        vistos.add(clave)
        resultado.append(nombre)
    return resultado
