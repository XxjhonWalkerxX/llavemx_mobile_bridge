# LlaveMX Mobile Bridge

Plugin de Open edX (Release Ulmo) que permite autenticar usuarios desde la app móvil Android de MéxicoX usando [Llave MX](https://www.gob.mx/llavemx), la identidad digital del Gobierno de México, mediante el flujo OAuth 2.0 Authorization Code con PKCE.

## Qué hace

El plugin actúa como puente entre la app Android y la API de LlaveMX. Expone dos endpoints en el LMS:

| Endpoint | Método | Función |
|----------|--------|---------|
| `/mobile/callback` | GET | Recibe el redirect de LlaveMX tras la autenticación y redirige a la app Android mediante deep link (`mx.aprende.android://oauth/callback`) |
| `/api/mobile/llavemx/login/` | POST | Recibe el `code` + `code_verifier` desde la app, hace el intercambio PKCE con LlaveMX, obtiene datos del usuario, crea/actualiza la cuenta en Open edX y emite un JWT válido |

## Flujo completo

```
App Android             Navegador             LlaveMX API            Este plugin             Open edX
    │                       │                      │                      │                      │
    │──1. Abre navegador───▶│                      │                      │                      │
    │   con URL de LlaveMX  │──2. Autenticación───▶│                      │                      │
    │   + PKCE challenge    │                      │                      │                      │
    │                       │◀─3. Redirect─────────│                      │                      │
    │                       │  /mobile/callback     │                      │                      │
    │                       │  ?code=XXX&state=YYY  │                      │                      │
    │                       │─────────────────────────────────────────────▶│                      │
    │                       │                      │            4. Genera HTML con deep link      │
    │◀──5. Deep link────────│                      │                      │                      │
    │   mx.aprende.android://oauth/callback?code=XXX&state=YYY            │                      │
    │                       │                      │                      │                      │
    │──6. POST /api/mobile/llavemx/login/─────────────────────────────────▶                      │
    │   { code, code_verifier, redirect_uri }      │                      │                      │
    │                       │                      │◀─7. obtenerToken─────│  (PKCE exchange)     │
    │                       │                      │──accessToken────────▶│                      │
    │                       │                      │◀─8. datosUsuario─────│                      │
    │                       │                      │──curp,email,nombre──▶│                      │
    │                       │                      │                      │──9. get_or_create───▶│
    │                       │                      │                      │   User + Profile     │
    │                       │                      │                      │──10. DOT → JWT──────▶│
    │                       │                      │                      │◀─JWT token───────────│
    │◀──11. { access_token: "eyJ...", token_type: "JWT" }─────────────────│                      │
    │                       │                      │                      │                      │
    │──12. Authorization: JWT eyJ... ──────────────────────────────────────────────────────────────▶
    │   (todas las APIs móviles)                   │                      │                      │
```

## Estructura del proyecto

```
llavemx_mobile_bridge/
├── pyproject.toml                  # Empaquetado + entry-point "lms.djangoapp"
└── llavemx_mobile_bridge/
    ├── __init__.py
    ├── apps.py                     # AppConfig con plugin_app → inyecta URLs en el LMS
    ├── urls.py                     # 2 rutas: /mobile/callback y /api/mobile/llavemx/login/
    ├── compat.py                   # Imports opcionales de Open edX (None si no están disponibles)
    ├── views.py                    # Flujo LlaveMX: intercambio PKCE, obtención de datos, emisión JWT
    ├── user_sync.py                # Lógica Open edX: buscar/crear/actualizar usuario
    └── templates/
        └── llavemx_mobile_bridge/
            └── callback.html       # Página HTML que abre la app Android via deep link
```

## Cómo se registra en Open edX

El plugin usa el sistema estándar de plugins de edx-platform:

1. **`pyproject.toml`** declara el entry-point `lms.djangoapp` → Open edX lo descubre al hacer `pip install`
2. **`apps.py`** define `plugin_app["url_config"]["lms.djangoapp"]` → el LMS inyecta las URLs automáticamente
3. No se necesita modificar ningún archivo de edx-platform

## Instalación

### En Tutor (producción/staging)

```bash
# Dentro del contenedor LMS
tutor local exec lms bash -c "pip install git+https://github.com/tu-org/llavemx_mobile_bridge.git"
tutor local restart lms
```

### Desarrollo local con volumen montado

```bash
tutor local exec lms bash -c "pip install -e /openedx/extra/llavemx_mobile_bridge/"
tutor local restart lms
```

## Configuración

### 1. Crear aplicación OAuth en Django Admin

Ir a `https://tu-dominio.com/admin/oauth2_provider/application/` y crear:

| Campo | Valor |
|-------|-------|
| **Name** | `LlaveMX Mobile` |
| **Client type** | Public |
| **Authorization grant type** | Resource owner password-based |
| **User** | Un usuario administrador existente |
| **Skip authorization** | ✅ |

> **Importante:** el nombre debe ser exactamente `LlaveMX Mobile` — el plugin busca la aplicación por este nombre.

### 2. Settings de Django

Los valores por defecto apuntan al **sandbox** de LlaveMX. Para producción, configurar en los settings del LMS (via plugin de Tutor o `lms.env.json`):

```python
# Client ID de la app registrada en LlaveMX
LLAVEMX_MOBILE_CLIENT_ID = "202602091646467055"  # sandbox por defecto

# URLs de la API de LlaveMX
# Sandbox (por defecto):
LLAVEMX_TOKEN_URL = "https://val-api-llave.infotec.mx/ws/rest/apps/oauth/obtenerToken"
LLAVEMX_USER_INFO_URL = "https://val-api-llave.infotec.mx/ws/rest/apps/oauth/datosUsuario"

# Producción:
# LLAVEMX_TOKEN_URL = "https://www.api.llave.gob.mx/ws/rest/apps/oauth/obtenerToken"
# LLAVEMX_USER_INFO_URL = "https://www.api.llave.gob.mx/ws/rest/apps/oauth/datosUsuario"

# Deep link scheme de la app Android (por defecto: mx.aprende.android)
LLAVEMX_ANDROID_DEEP_LINK_SCHEME = "mx.aprende.android"
```

## Endpoints

### `GET /mobile/callback`

Recibe el redirect de LlaveMX después de que el usuario se autentica en el navegador.

**Query params:**
- `code` — Código de autorización JWT de LlaveMX
- `state` — Estado CSRF generado por la app

**Respuesta:** Página HTML que abre automáticamente la app Android via deep link.

### `POST /api/mobile/llavemx/login/`

Intercambia el código de autorización por un JWT de Open edX.

**Content-Type:** `application/x-www-form-urlencoded` o `application/json`

**Body:**

| Campo | Tipo | Requerido | Descripción |
|-------|------|-----------|-------------|
| `code` | string | Sí | Código de autorización recibido de LlaveMX |
| `code_verifier` | string | Sí | Verificador PKCE generado por la app |
| `redirect_uri` | string | No | URI de redirección usada (ej: `https://dev.mexicox.gob.mx/mobile/callback`) |

**Respuesta exitosa (200):**

```json
{
  "access_token": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9...",
  "token_type": "JWT",
  "expires_in": 3600,
  "scope": "profile email",
  "refresh_token": "opaque-refresh-token"
}
```

**Errores posibles:**

| Código | Causa |
|--------|-------|
| 400 | Faltan `code` o `code_verifier`, o LlaveMX no devolvió email |
| 403 | CURP duplicado con múltiples cuentas activas — contactar soporte |
| 500 | No existe la aplicación OAuth "LlaveMX Mobile" en Django Admin |
| 501 | Módulo `oauth_dispatch` no disponible |
| 502 | Error al comunicarse con la API de LlaveMX |
| 504 | Timeout conectando con LlaveMX |

## Qué hace con los usuarios

La búsqueda sigue este orden (alineado con el pipeline web):

1. **Por CURP** — busca en `ExtraInfo.curp`. Si hay múltiples cuentas activas con el mismo CURP, bloquea el login (error 403).
2. **Por email** — fallback si no se encuentra por CURP.
3. **Creación** — si no existe, crea una cuenta nueva con:
   - Username: CURP (o sufijo `_1`, `_2`... si ya está tomado)
   - Contraseña aleatoria (`secrets.token_urlsafe(30)`) — el usuario no puede hacer login con contraseña
   - `is_active=True` desde el inicio
   - `Registration` con `activation_key='ACTIVATED'` via `bulk_create` (evita señales Celery que desactivarían la cuenta)

## Desarrollo

```bash
git clone https://github.com/tu-org/llavemx_mobile_bridge.git
cd llavemx_mobile_bridge
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

## Licencia

AGPL-3.0
