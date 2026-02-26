"""
Services for LlaveMX Mobile Bridge plugin.

Este módulo contiene toda la lógica de negocio relacionada con LlaveMX,
manteniendo el código limpio y separado de las vistas.
"""
import logging
from typing import Optional, Dict, Any

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

# URLs de LlaveMX (usar settings para producción)
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


class LlaveMxServiceError(Exception):
    """Excepción personalizada para errores del servicio LlaveMX."""
    pass


class LlaveMxService:
    """
    Servicio para interactuar con la API de LlaveMX.
    """

    @staticmethod
    def exchange_code_for_token(
        code: str,
        code_verifier: str,
        redirect_uri: str,
        client_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Intercambia el código de autorización PKCE por un token de acceso.

        Args:
            code: Código de autorización recibido de LlaveMX.
            code_verifier: Verificador PKCE.
            redirect_uri: URI de redirección usada en la autorización.
            client_id: ID del cliente LlaveMX (opcional, usa settings por defecto).

        Returns:
            Diccionario con los datos del token.

        Raises:
            LlaveMxServiceError: Si hay un error en el intercambio.
        """
        if client_id is None:
            client_id = getattr(settings, "LLAVEMX_MOBILE_CLIENT_ID", None)

        if not client_id:
            raise LlaveMxServiceError("LLAVEMX_MOBILE_CLIENT_ID no está configurado")

        payload = {
            "grantType": "authorization_code",
            "code": code,
            "redirectUri": redirect_uri,
            "clientId": client_id,
            "codeVerifier": code_verifier,
        }

        try:
            response = requests.post(
                LLAVEMX_TOKEN_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            logger.error(f"Error al intercambiar código por token: {e}")
            raise LlaveMxServiceError(f"Error comunicándose con LlaveMX: {e}")

    @staticmethod
    def get_user_info(access_token: str) -> Dict[str, Any]:
        """
        Obtiene la información del usuario desde LlaveMX.

        Args:
            access_token: Token de acceso de LlaveMX.

        Returns:
            Diccionario con los datos del usuario.

        Raises:
            LlaveMxServiceError: Si hay un error obteniendo los datos.
        """
        try:
            response = requests.get(
                LLAVEMX_USER_INFO_URL,
                headers={"accessToken": access_token},
                timeout=30
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            logger.error(f"Error al obtener datos de usuario: {e}")
            raise LlaveMxServiceError(f"Error obteniendo datos de usuario: {e}")

    @staticmethod
    def extract_user_data(user_info: Dict[str, Any]) -> Dict[str, str]:
        """
        Extrae los datos relevantes del usuario para Open edX.

        Args:
            user_info: Datos crudos del usuario de LlaveMX.

        Returns:
            Diccionario con email, username, first_name, last_name.
        """
        return {
            "email": user_info.get("correo", ""),
            "username": user_info.get("curp") or user_info.get("login", ""),
            "first_name": user_info.get("nombre", ""),
            "last_name": user_info.get("primerApellido", ""),
        }
