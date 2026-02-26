# LlaveMX Mobile Bridge

Plugin de Open edX para autenticación móvil con LlaveMX (compatible con Ulmo).

## Descripción

Este plugin permite que aplicaciones móviles autentiquen usuarios usando LlaveMX con el flujo OAuth PKCE. Obtiene los datos del usuario de LlaveMX y emite tokens de acceso válidos para Open edX.

## Características

- ✅ Compatible con Open edX Ulmo
- ✅ Autenticación PKCE segura
- ✅ Creación automática de usuarios
- ✅ Emisión de tokens OAuth de Open edX

## Instalación

### Usando pip

```bash
pip install git+https://github.com/tu-usuario/llavemx_mobile_bridge.git
```

### En Tutor (Open edX)

Agregar al archivo de configuración o en un plugin de Tutor:

```bash
pip install git+https://github.com/tu-usuario/llavemx_mobile_bridge.git
```

## Configuración

### 1. Variables de entorno / Django settings

Agregar en la configuración de Open edX:

```python
LLAVEMX_MOBILE_CLIENT_ID = "tu-client-id-de-llavemx"

# Opcional: URLs personalizadas de LlaveMX
LLAVEMX_TOKEN_URL = "https://val-api-llave.infotec.mx/ws/rest/apps/oauth/obtenerToken"
LLAVEMX_USER_INFO_URL = "https://val-api-llave.infotec.mx/ws/rest/apps/oauth/datosUsuario"
```

### 2. Crear aplicación OAuth en Open edX

Crear una aplicación OAuth en Django Admin con el nombre **"LlaveMX Mobile"**:

1. Ir a `/admin/oauth2_provider/application/`
2. Crear nueva aplicación:
   - **Name**: `LlaveMX Mobile`
   - **Client type**: Confidential
   - **Authorization grant type**: Client credentials
   - **Skip authorization**: ✅

## Uso

### Endpoint

```
POST /api/mobile/llavemx/login/
```

### Request Body

```json
{
  "code": "código-de-autorización-de-llavemx",
  "code_verifier": "verificador-pkce",
  "redirect_uri": "tu-app://callback"
}
```

### Response (éxito)

```json
{
  "access_token": "token-de-open-edx",
  "token_type": "Bearer",
  "expires_in": 36000,
  "scope": "profile email"
}
```

## Flujo de Autenticación

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   App Móvil │     │   LlaveMX   │     │  Este Plugin │     │  Open edX   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │                   │
       │  1. Auth PKCE     │                   │                   │
       │──────────────────>│                   │                   │
       │                   │                   │                   │
       │  2. Code + Verifier                   │                   │
       │<──────────────────│                   │                   │
       │                   │                   │                   │
       │  3. POST /api/mobile/llavemx/login/   │                   │
       │──────────────────────────────────────>│                   │
       │                   │                   │                   │
       │                   │  4. Exchange Token│                   │
       │                   │<──────────────────│                   │
       │                   │                   │                   │
       │                   │  5. User Data     │                   │
       │                   │<──────────────────│                   │
       │                   │                   │                   │
       │                   │                   │  6. Create Token  │
       │                   │                   │──────────────────>│
       │                   │                   │                   │
       │  7. Open edX Token                    │                   │
       │<──────────────────────────────────────│                   │
       │                   │                   │                   │
```

## Desarrollo

```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/llavemx_mobile_bridge.git
cd llavemx_mobile_bridge

# Crear entorno virtual
python -m venv venv
source venv/bin/activate

# Instalar dependencias de desarrollo
pip install -e ".[dev]"
```

## Licencia

AGPL-3.0
