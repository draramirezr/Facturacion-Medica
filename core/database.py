"""Conexiones, consultas y transacciones de base de datos."""

import logging
from contextlib import contextmanager
from functools import wraps

import pymysql
from flask import g, request

from core.config import DATABASE_CONFIG, ENVIRONMENT

pymysql.install_as_MySQLdb()

logger = logging.getLogger(__name__)


def get_db_connection():
    """Obtener una conexión reutilizable durante el contexto Flask."""
    if 'db_conn' not in g:
        config = DATABASE_CONFIG.copy()
        config['cursorclass'] = pymysql.cursors.DictCursor
        config['autocommit'] = True
        g.db_conn = pymysql.connect(**config)
        logger.debug('Nueva conexión a BD creada')
    return g.db_conn


def close_db(error=None):
    """Cerrar la conexión al finalizar el contexto de aplicación."""
    db_conn = g.pop('db_conn', None)
    if db_conn is not None:
        try:
            db_conn.close()
            logger.debug('Conexión a BD cerrada')
        except Exception as exc:
            logger.error('Error al cerrar conexión: %s', exc)


def _normalize_params(params):
    if params is not None and not isinstance(params, (tuple, list)):
        logger.warning('Params debe ser tupla o lista, recibido: %s', type(params))
        return (params,)
    return params


def _handle_database_error(error, query, operation):
    conn = get_db_connection()
    try:
        conn.rollback()
    except Exception:
        pass
    logger.error(
        'Error %s: %s - Query: %s...',
        operation,
        error,
        (query or '')[:100],
        exc_info=not isinstance(error, pymysql.Error),
    )
    if g.get('db_transaction_active', False) or ENVIRONMENT == 'development':
        raise error
    return None


def execute_query(query, params=None, fetch='one'):
    """Ejecutar una consulta y retornar uno, todos o ningún resultado."""
    cursor = None
    if not query or not query.strip():
        logger.error('Intento de ejecutar query vacía')
        return None
    params = _normalize_params(params)
    if params and any(
        isinstance(param, str)
        and (';' in param or '--' in param or '/*' in param)
        for param in params
    ):
        logger.warning('Posible intento de SQL injection detectado en params')
    try:
        cursor = get_db_connection().cursor()
        cursor.execute(query, params or ())
        if fetch == 'one':
            return cursor.fetchone()
        if fetch == 'all':
            return cursor.fetchall()
        return None
    except Exception as error:
        return _handle_database_error(error, query, 'SQL en execute_query')
    finally:
        if cursor:
            cursor.close()


def execute_update(query, params=None):
    """Ejecutar INSERT, UPDATE o DELETE y retornar ``lastrowid``."""
    cursor = None
    if not query or not query.strip():
        logger.error('Intento de ejecutar update con query vacía')
        return None
    params = _normalize_params(params)
    if params and any(
        isinstance(param, str)
        and (';' in param or '--' in param or '/*' in param)
        for param in params
    ):
        logger.warning('Posible intento de SQL injection detectado en params')
    try:
        cursor = get_db_connection().cursor()
        cursor.execute(query, params or ())
        return cursor.lastrowid
    except Exception as error:
        return _handle_database_error(error, query, 'SQL en execute_update')
    finally:
        if cursor:
            cursor.close()


@contextmanager
def database_transaction():
    """Agrupar helpers en una única transacción atómica."""
    conn = get_db_connection()
    if g.get('db_transaction_active', False):
        yield conn
        return

    g.db_transaction_active = True
    conn.begin()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        g.pop('db_transaction_active', None)


def transactional_methods(*methods):
    """Aplicar una transacción a métodos HTTP concretos."""
    protected_methods = {method.upper() for method in methods}

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if request.method not in protected_methods:
                return func(*args, **kwargs)
            with database_transaction():
                return func(*args, **kwargs)

        wrapper.transactional_methods = frozenset(protected_methods)
        return wrapper

    return decorator


def init_database(app):
    """Registrar el cierre de conexiones."""
    app.teardown_appcontext(close_db)
