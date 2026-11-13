# Fase 1 — Infraestructura servicio e-CF externo

## Migración (no ejecutar en producción sin autorización)

```powershell
py -3 crear_modulo_external_ecf_integracion.py
```

## Habilitación local

```env
EXTERNAL_ECF_ENABLED=true
EXTERNAL_ECF_JWT_SECRET=<clave-de-al-menos-32-caracteres>
EXTERNAL_ECF_TOKEN_TTL=3600
EXTERNAL_ECF_ENVIRONMENT=PRUEBAS
```

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| POST | `/api/Autenticacion` | Contrato HKA (JWT en respuesta) |
| GET | `/external-ecf/health` | Salud del módulo |

## Alta manual RicoHotDog (ejemplo)

Tras migración, insertar cliente, emisor (`tenant_id` existente), credencial con `password_hash` generado con `hash_integration_password` en consola Python.

## Pruebas

```powershell
py -3 -m unittest tests.test_external_ecf_authentication -v
```
