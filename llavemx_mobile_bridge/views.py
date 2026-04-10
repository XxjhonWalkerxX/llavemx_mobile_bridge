"""
LlaveMX Mobile Bridge — Backend de autenticación móvil (PKCE).
Integración oficial con Open edX mediante el flujo OAuth2 PKCE para apps nativas.

Esta implementación sigue el Manual Técnico LlaveMX (Integración Apps Nativas v2.1):
- OAuth2 Authorization Code CON PKCE (sin client_secret)
- El intercambio de code por token se hace SOLO desde el backend (servidor)
- El token de LlaveMX nunca se expone a la app ni al frontend

NOTAS DE SEGURIDAD IMPLEMENTADAS (Manual LlaveMX Apps Nativas v2.1):

1) IPs homologadas en producción (Sección 3.1)
   - En producción, las IPs públicas del servidor deben entregarse a la ATDT
     para ser homologadas antes de activar el ambiente productivo de LlaveMX.

2) PKCE: state y code_verifier (Sección 3.2)
   - El parámetro "state" es un valor único por solicitud para prevenir CSRF.
   - El "code_verifier" no debe revelarse ni almacenarse permanentemente;
     se usa una sola vez para el intercambio del code.
   - code_challenge = Base64UrlEncode(SHA256(ASCII(code_verifier)))
   - Generados y validados en la app Android (LlaveMxAuthManager / LlaveMxCallbackActivity).

3) Navegador nativo del dispositivo (Sección 3.3)
   - La autenticación DEBE realizarse en el navegador web nativo del dispositivo,
     NO en web-views embebidos. Esto lo gestiona la app Android con Chrome Custom Tabs.

4) Validación del state y vigencia del code (Sección 3.4)
   - El "state" recibido en el callback debe coincidir con el enviado (anti-CSRF).
     Esta validación la realiza LlaveMxCallbackActivity en la app Android.
   - El "code" tiene vigencia de 1 minuto; el backend debe intercambiarlo de inmediato.

5) Intercambio de code por token (Sección 3.5)
   - El "codeVerifier" se envía como parte del body al intercambiar el code por token.
   - El access_token tiene vigencia de 15 minutos.
   - En apps nativas NO se entrega "secret_code" (client_secret); se usa PKCE en su lugar.

6) Manejo seguro del token de acceso (Sección 4.1)
   - El token de LlaveMX NO se expone al frontend ni se retorna a la app.
   - Este backend lo usa solo internamente para obtener datos del usuario.
   - Si LlaveMX responde con error (incluido invalid_token), se deniega el acceso.
   - La app gestiona la sesión mediante el JWT emitido por Open edX, no por el token LlaveMX.

7) Cierre de sesión remoto en apps nativas (Sección 5.1)
   - El endpoint de cierre de sesión para apps nativas es diferente del web:
     /ws/rest/apps/auth/cerrarSesion (en lugar de /ws/rest/oauth/cerrarSesion)
   - En producción se presenta HTTP 411 (Length Required) si no se envía body;
     solución: enviar body "{}" explícitamente.
"""
import logging
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.parsers import FormParser, JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .compat import Application, adapters, create_dot_access_token, create_jwt_token_dict
from .user_sync import LlaveMXSyncError, get_or_create_openedx_user

logger = logging.getLogger(__name__)

def _required_setting(name):
    """Lee un setting de Django en tiempo de petición (no en importación)."""
    from django.core.exceptions import ImproperlyConfigured
    value = getattr(settings, name, None)
    if not value:
        raise ImproperlyConfigured(
            f"[LlaveMX Mobile Bridge] Falta configurar '{name}' en el Tutor plugin. "
            f"Ejecuta: tutor config save --set {name}=<valor>"
        )
    return value


@method_decorator(csrf_exempt, name='dispatch')
class LlaveMxMobileLogin(APIView):
    """
    Endpoint para autenticación móvil con LlaveMX usando PKCE.

    Flujo:
        1. Recibe code + code_verifier de la app Android
        2. Intercambia con LlaveMX → access_token  (Sección 3.5)
        3. Obtiene datos del usuario desde LlaveMX  (Sección 4.1)
        4. Busca o crea la cuenta en Open edX
        5. Emite JWT de Open edX → retorna a la app

    Acepta JSON y form-urlencoded (compatibilidad con Retrofit).
    """
    authentication_classes = []
    permission_classes = []
    parser_classes = [JSONParser, FormParser]

    def post(self, request):
        code = request.data.get("code")
        code_verifier = request.data.get("code_verifier")
        redirect_uri = request.data.get("redirect_uri")
        logger.info("[LlaveMX Mobile] Login attempt - redirect_uri: %s", redirect_uri)

        if not code or not code_verifier:
            return Response(
                {"error": "Missing parameters: code and code_verifier are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # NOTA DE SEGURIDAD (Sección 3.5):
            # Intercambio desde el backend con codeVerifier (PKCE). Sin client_secret.
            # El code tiene vigencia de 1 minuto (Sección 3.4) — se intercambia de inmediato.
            access_token = self._exchange_code(code, code_verifier, redirect_uri)

            # NOTA DE SEGURIDAD (Sección 4.1):
            # El access_token se usa solo aquí, en el backend. No se retorna a la app.
            user_data = self._fetch_user_data(access_token)

            uid = user_data.get("idUsuario")
            email = user_data.get("correo")

            user = get_or_create_openedx_user(request, user_data, access_token, uid)

            # NOTA DE SEGURIDAD (Sección 4.1):
            # Se emite un JWT propio de Open edX. El token de LlaveMX no se incluye en la respuesta.
            jwt_token_dict = self._emit_jwt(request, user)

            logger.info("[LlaveMX Mobile] Login successful for %s", email)
            return Response(jwt_token_dict)

        except LlaveMXSyncError as e:
            return Response({"error": e.error}, status=e.http_status)
        except requests.exceptions.Timeout:
            logger.error("[LlaveMX Mobile] Timeout connecting to LlaveMX")
            return Response({"error": "LlaveMX service timeout"}, status=status.HTTP_504_GATEWAY_TIMEOUT)
        except requests.exceptions.RequestException as e:
            logger.error("[LlaveMX Mobile] Request error: %s", e)
            return Response({"error": f"Error communicating with LlaveMX: {e}"}, status=status.HTTP_502_BAD_GATEWAY)
        except Exception as e:
            logger.exception("[LlaveMX Mobile] Unexpected error: %s", e)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _exchange_code(self, code, code_verifier, redirect_uri):
        """
        Intercambia el authorization code por un access_token usando PKCE.
        (Manual LlaveMX Apps Nativas v2.1, Sección 3.5)
        """
        response = requests.post(
            _required_setting("LLAVEMX_TOKEN_URL"),
            json={
                "grantType": "authorization_code",
                "code": code,
                "redirectUri": redirect_uri,
                "clientId": _required_setting("LLAVEMX_MOBILE_CLIENT_ID"),
                "codeVerifier": code_verifier,
            },
            headers={"Content-Type": "application/json"},
            timeout=30
        )

        if not response.ok:
            logger.error("[LlaveMX Mobile] Token exchange failed: %s - %s", response.status_code, response.text)
            raise requests.exceptions.RequestException(f"Token exchange failed: {response.text}")

        token_data = response.json()
        access_token = token_data.get("accessToken")

        if not access_token:
            logger.error("[LlaveMX Mobile] No accessToken in response: %s", token_data)
            raise requests.exceptions.RequestException("Invalid response from LlaveMX - no accessToken")

        return access_token

    def _fetch_user_data(self, access_token):
        """
        Obtiene los datos del usuario usando el access_token de LlaveMX.
        (Manual LlaveMX Apps Nativas v2.1, Sección 4.1)
        """
        response = requests.get(
            _required_setting("LLAVEMX_USER_INFO_URL"),
            headers={"accessToken": access_token},
            timeout=30
        )

        if not response.ok:
            logger.error("[LlaveMX Mobile] User data fetch failed: %s - %s", response.status_code, response.text)
            raise requests.exceptions.RequestException("Failed to fetch user data from LlaveMX")

        return response.json()

    def _emit_jwt(self, request, user):
        """
        Emite un JWT de Open edX para el usuario autenticado.
        Este token es independiente del token de LlaveMX.
        """
        if create_dot_access_token is None or Application is None:
            raise Exception("Open edX OAuth not available")

        try:
            client = Application.objects.get(name="LlaveMX Mobile")
        except Application.DoesNotExist:
            logger.error("[LlaveMX Mobile] OAuth Application 'LlaveMX Mobile' not found")
            raise Exception("OAuth application not configured. Create 'LlaveMX Mobile' in Django Admin.")

        dot_token_dict = create_dot_access_token(
            request=request,
            user=user,
            client=client,
            scopes="profile email"
        )

        return create_jwt_token_dict(
            dot_token_dict,
            adapters.DOTAdapter(),
            use_asymmetric_key=True,
        )




class LlaveMxMobileCallback(View):
    """
    Recibe el callback de LlaveMX y redirige a la app móvil via deep link.

    LlaveMX redirige aquí tras la autenticación:
        GET /mobile/callback?code=XXX&state=YYY

    Esta vista genera una página HTML que abre la app Android:
        mx.aprende.android://oauth/callback?code=XXX&state=YYY
    """

    def get(self, request):
        code = request.GET.get("code")
        state = request.GET.get("state")
        error = request.GET.get("error")
        error_description = request.GET.get("error_description", "")
        logger.info("[LlaveMX Callback] Received - code: %s, state: %s, error: %s", bool(code), bool(state), error)

        if error:
            context = {
                "title": "Error de autenticación",
                "message": error_description or error,
                "button_text": "Volver a la app",
                "deep_link_scheme": _required_setting("LLAVEMX_ANDROID_DEEP_LINK_SCHEME"),
                "dl_error": error,
                "dl_error_description": error_description,
                "dl_code": "",
                "dl_state": "",
            }
        elif code:
            context = {
                "title": "Autenticación exitosa",
                "message": "Redirigiendo a la aplicación...",
                "button_text": "Abrir app",
                "deep_link_scheme": _required_setting("LLAVEMX_ANDROID_DEEP_LINK_SCHEME"),
                "dl_error": "",
                "dl_error_description": "",
                "dl_code": code,
                "dl_state": state or "",
            }
        else:
            context = {
                "title": "Error",
                "message": "No se recibió código de autorización",
                "button_text": "Volver a la app",
                "deep_link_scheme": _required_setting("LLAVEMX_ANDROID_DEEP_LINK_SCHEME"),
                "dl_error": "no_code",
                "dl_error_description": "",
                "dl_code": "",
                "dl_state": "",
            }

        return render(request, "llavemx_mobile_bridge/callback.html", context)
