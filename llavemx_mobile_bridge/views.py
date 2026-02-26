"""
Views for LlaveMX Mobile Bridge plugin.
"""
import logging

import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
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


class LlaveMxMobileLogin(APIView):
    """
    Endpoint para autenticación móvil con LlaveMX usando PKCE.

    Este endpoint recibe el código de autorización y el code_verifier
    del flujo PKCE, los intercambia por un token de LlaveMX, obtiene
    los datos del usuario y emite un token de Open edX.
    """
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        """
        Procesa el login móvil con LlaveMX.

        Parámetros esperados en el body:
            - code: Código de autorización de LlaveMX
            - code_verifier: Verificador PKCE
            - redirect_uri: URI de redirección usada

        Returns:
            Token de acceso de Open edX para el usuario autenticado.
        """
        code = request.data.get("code")
        code_verifier = request.data.get("code_verifier")
        redirect_uri = request.data.get("redirect_uri")

        # Validación de parámetros
        if not code or not code_verifier:
            return Response(
                {"error": "Missing parameters: code and code_verifier are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # 1️⃣ Intercambio PKCE con LlaveMX
            token_response = requests.post(
                "https://val-api-llave.infotec.mx/ws/rest/apps/oauth/obtenerToken",
                json={
                    "grantType": "authorization_code",
                    "code": code,
                    "redirectUri": redirect_uri,
                    "clientId": settings.LLAVEMX_MOBILE_CLIENT_ID,
                    "codeVerifier": code_verifier,
                },
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            token_response.raise_for_status()
            token_data = token_response.json()
            access_token = token_data.get("accessToken")

            if not access_token:
                logger.error("No se recibió accessToken de LlaveMX")
                return Response(
                    {"error": "Invalid response from LlaveMX"},
                    status=status.HTTP_502_BAD_GATEWAY
                )

            # 2️⃣ Obtener datos del usuario
            user_response = requests.get(
                "https://val-api-llave.infotec.mx/ws/rest/apps/oauth/datosUsuario",
                headers={"accessToken": access_token},
                timeout=30
            )
            user_response.raise_for_status()
            user_data = user_response.json()

            email = user_data.get("correo")
            username = user_data.get("curp") or user_data.get("login")

            if not email:
                return Response(
                    {"error": "No email received from LlaveMX"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Crear o obtener usuario
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "username": username,
                    "first_name": user_data.get("nombre", ""),
                    "last_name": user_data.get("primerApellido", ""),
                }
            )

            if created:
                user.set_unusable_password()
                user.save()
                logger.info(f"Usuario creado: {username}")

            # 3️⃣ Emitir token Open edX
            if create_dot_access_token is None or Application is None:
                return Response(
                    {"error": "Open edX OAuth not available"},
                    status=status.HTTP_501_NOT_IMPLEMENTED
                )

            try:
                client = Application.objects.get(name="LlaveMX Mobile")
            except Application.DoesNotExist:
                logger.error("Aplicación OAuth 'LlaveMX Mobile' no encontrada")
                return Response(
                    {"error": "OAuth application not configured"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            edx_token = create_dot_access_token(
                request=request,
                user=user,
                client=client,
                scopes="profile email"
            )

            return Response(edx_token)

        except requests.exceptions.Timeout:
            logger.error("Timeout conectando con LlaveMX")
            return Response(
                {"error": "LlaveMX service timeout"},
                status=status.HTTP_504_GATEWAY_TIMEOUT
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Error comunicándose con LlaveMX: {e}")
            return Response(
                {"error": "Error communicating with LlaveMX"},
                status=status.HTTP_502_BAD_GATEWAY
            )
        except Exception as e:
            logger.exception(f"Error inesperado en login LlaveMX: {e}")
            return Response(
                {"error": "Internal server error"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
