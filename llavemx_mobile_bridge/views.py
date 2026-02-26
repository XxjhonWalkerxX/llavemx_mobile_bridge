"""
Views for LlaveMX Mobile Bridge plugin.
"""
import logging

import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import JSONParser, FormParser
from django.conf import settings
from django.contrib.auth import get_user_model

try:
    from openedx.core.djangoapps.oauth_dispatch.api import create_dot_access_token
    from oauth2_provider.models import Application
except ImportError:
    # Para desarrollo local sin Open edX
    create_dot_access_token = None
    Application = None

logger = logging.getLogger(__name__)

User = get_user_model()

# URLs configurables desde settings (sandbox por defecto)
LLAVEMX_TOKEN_URL = getattr(
    settings,
    "LLAVEMX_TOKEN_URL",
    "https://val-api-llave.infotec.mx/ws/rest/apps/oauth/obtenerToken"
)
LLAVEMX_USER_INFO_URL = getattr(
    settings,
    "LLAVEMX_USER_INFO_URL",
    "https://val-api-llave.infotec.mx/ws/rest/apps/oauth/datosUsuario"
)
LLAVEMX_MOBILE_CLIENT_ID = getattr(
    settings,
    "LLAVEMX_MOBILE_CLIENT_ID",
    "202602091646467055"  # Sandbox default
)


class LlaveMxMobileLogin(APIView):
    """
    Endpoint para autenticación móvil con LlaveMX usando PKCE.

    Este endpoint recibe el código de autorización y el code_verifier
    del flujo PKCE, los intercambia por un token de LlaveMX, obtiene
    los datos del usuario y emite un token de Open edX.
    
    Acepta tanto JSON como form-urlencoded (para compatibilidad con Retrofit).
    """
    authentication_classes = []
    permission_classes = []
    parser_classes = [JSONParser, FormParser]  # Acepta JSON y form-urlencoded

    def post(self, request):
        """
        Procesa el login móvil con LlaveMX.

        Parámetros esperados en el body (JSON o form-urlencoded):
            - code: Código de autorización de LlaveMX
            - code_verifier: Verificador PKCE
            - redirect_uri: URI de redirección usada

        Returns:
            Token de acceso de Open edX para el usuario autenticado.
        """
        code = request.data.get("code")
        code_verifier = request.data.get("code_verifier")
        redirect_uri = request.data.get("redirect_uri")

        logger.info(f"[LlaveMX Mobile] Login attempt - redirect_uri: {redirect_uri}")

        # Validación de parámetros
        if not code or not code_verifier:
            logger.warning("[LlaveMX Mobile] Missing parameters")
            return Response(
                {"error": "Missing parameters: code and code_verifier are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # 1️⃣ Intercambio PKCE con LlaveMX
            logger.info(f"[LlaveMX Mobile] Exchanging code with LlaveMX at {LLAVEMX_TOKEN_URL}")
            token_response = requests.post(
                LLAVEMX_TOKEN_URL,
                json={
                    "grantType": "authorization_code",
                    "code": code,
                    "redirectUri": redirect_uri,
                    "clientId": LLAVEMX_MOBILE_CLIENT_ID,
                    "codeVerifier": code_verifier,
                },
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if not token_response.ok:
                logger.error(f"[LlaveMX Mobile] Token exchange failed: {token_response.status_code} - {token_response.text}")
                return Response(
                    {"error": f"LlaveMX token exchange failed: {token_response.text}"},
                    status=status.HTTP_502_BAD_GATEWAY
                )
            
            token_data = token_response.json()
            access_token = token_data.get("accessToken")
            
            logger.info(f"[LlaveMX Mobile] Token response keys: {token_data.keys()}")

            if not access_token:
                logger.error(f"[LlaveMX Mobile] No accessToken in response: {token_data}")
                return Response(
                    {"error": "Invalid response from LlaveMX - no accessToken"},
                    status=status.HTTP_502_BAD_GATEWAY
                )

            # 2️⃣ Obtener datos del usuario
            logger.info(f"[LlaveMX Mobile] Fetching user data from {LLAVEMX_USER_INFO_URL}")
            user_response = requests.get(
                LLAVEMX_USER_INFO_URL,
                headers={"accessToken": access_token},
                timeout=30
            )
            
            if not user_response.ok:
                logger.error(f"[LlaveMX Mobile] User data fetch failed: {user_response.status_code} - {user_response.text}")
                return Response(
                    {"error": "Failed to fetch user data from LlaveMX"},
                    status=status.HTTP_502_BAD_GATEWAY
                )
            
            user_data = user_response.json()
            logger.info(f"[LlaveMX Mobile] User data keys: {user_data.keys()}")

            email = user_data.get("correo")
            curp = user_data.get("curp")
            username = curp or user_data.get("login") or email.split("@")[0] if email else None

            if not email:
                logger.error(f"[LlaveMX Mobile] No email in user data: {user_data}")
                return Response(
                    {"error": "No email received from LlaveMX"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 3️⃣ Crear o obtener usuario
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "username": self._unique_username(username),
                    "first_name": user_data.get("nombre", ""),
                    "last_name": f"{user_data.get('primerApellido', '')} {user_data.get('segundoApellido', '')}".strip(),
                }
            )

            if created:
                user.set_unusable_password()
                user.save()
                logger.info(f"[LlaveMX Mobile] Usuario creado: {user.username} ({email})")
            else:
                logger.info(f"[LlaveMX Mobile] Usuario existente: {user.username} ({email})")

            # 4️⃣ Emitir token Open edX
            if create_dot_access_token is None or Application is None:
                logger.error("[LlaveMX Mobile] Open edX OAuth not available")
                return Response(
                    {"error": "Open edX OAuth not available"},
                    status=status.HTTP_501_NOT_IMPLEMENTED
                )

            try:
                client = Application.objects.get(name="LlaveMX Mobile")
            except Application.DoesNotExist:
                logger.error("[LlaveMX Mobile] OAuth Application 'LlaveMX Mobile' not found")
                return Response(
                    {"error": "OAuth application not configured. Create 'LlaveMX Mobile' in Django Admin."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            edx_token = create_dot_access_token(
                request=request,
                user=user,
                client=client,
                scopes="profile email"
            )

            logger.info(f"[LlaveMX Mobile] Login successful for {email}")
            return Response(edx_token)

        except requests.exceptions.Timeout:
            logger.error("[LlaveMX Mobile] Timeout connecting to LlaveMX")
            return Response(
                {"error": "LlaveMX service timeout"},
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"[LlaveMX Mobile] Request error: {e}")
            return Response(
                {"error": f"Error communicating with LlaveMX: {str(e)}"},
                status=status.HTTP_502_BAD_GATEWAY
            )
        except Exception as e:
            logger.exception(f"[LlaveMX Mobile] Unexpected error: {e}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _unique_username(self, base_username: str) -> str:
        """
        Genera un username único agregando un sufijo si es necesario.
        """
        if not base_username:
            base_username = "llavemx_user"
        
        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}_{counter}"
            counter += 1
        return username
