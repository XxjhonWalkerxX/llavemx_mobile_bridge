"""
Views for LlaveMX Mobile Bridge plugin.
"""
import json
import logging
from urllib.parse import urlencode

import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import JSONParser, FormParser
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.utils.translation import get_language
from django.views import View
from django.views.decorators.csrf import csrf_exempt

try:
    from openedx.core.djangoapps.oauth_dispatch.api import create_dot_access_token
    from openedx.core.djangoapps.oauth_dispatch.jwt import create_jwt_token_dict
    from openedx.core.djangoapps.oauth_dispatch import adapters
    from oauth2_provider.models import Application
except ImportError:
    # Para desarrollo local sin Open edX
    create_dot_access_token = None
    create_jwt_token_dict = None
    adapters = None
    Application = None

try:
    from common.djangoapps.student.models import UserProfile, Registration
    from common.djangoapps.student.models import create_comments_service_user
except ImportError:
    UserProfile = None
    Registration = None
    create_comments_service_user = None

try:
    from social_django.models import UserSocialAuth
except ImportError:
    UserSocialAuth = None

try:
    from openedx.core.djangoapps.user_api import preferences as preferences_api
    LANGUAGE_KEY = "pref-lang"
except ImportError:
    preferences_api = None
    LANGUAGE_KEY = None

try:
    from common.djangoapps.student.models import UserAttribute
except ImportError:
    UserAttribute = None

try:
    from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
except ImportError:
    configuration_helpers = None

try:
    from custom_reg_form.models import ExtraInfo
except Exception:
    ExtraInfo = None

try:
    from users.models import LlaveMXBlockedLogin
except Exception:
    LlaveMXBlockedLogin = None

GENERIC_CURP = "XEXX010101HDFXXX04"

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


@method_decorator(csrf_exempt, name='dispatch')
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
            curp = (user_data.get("curp") or "").strip()
            uid = user_data.get("idUsuario")
            es_extranjero = bool(user_data.get("esExtranjero", False))

            # Extranjeros sin CURP → asignar CURP genérico (alineado con web)
            if es_extranjero and not curp:
                curp = GENERIC_CURP
                logger.info("[LlaveMX Mobile] Usuario extranjero sin CURP, asignando genérico.")

            username = curp or user_data.get("login") or (email.split("@")[0] if email else None)

            if not email:
                logger.error(f"[LlaveMX Mobile] No email in user data: {user_data}")
                return Response(
                    {"error": "No email received from LlaveMX"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 3️⃣ Buscar usuario existente (primero por CURP, luego por email)
            user = None
            created = False

            # 3a) Asociación por CURP (alineado con pipeline web)
            if curp and curp.upper() != GENERIC_CURP and ExtraInfo is not None:
                matches = (
                    ExtraInfo.objects
                    .filter(curp__iexact=curp)
                    .select_related("user")
                )
                if matches.exists():
                    users_by_curp = [ei.user for ei in matches if ei.user]
                    active_users = [u for u in users_by_curp if u.is_active]

                    # BLOQUEO: múltiples cuentas activas con mismo CURP
                    if len(active_users) > 1:
                        logger.error(
                            "[LlaveMX Mobile][BLOCKED] CURP duplicado con múltiples cuentas activas. "
                            "curp=%s users=%s",
                            curp,
                            [u.id for u in active_users],
                        )
                        if LlaveMXBlockedLogin and uid:
                            try:
                                LlaveMXBlockedLogin.objects.update_or_create(
                                    uid=str(uid),
                                    defaults={
                                        "curp": curp,
                                        "email": email,
                                        "resolved": False,
                                        "resolved_at": None,
                                        "resolved_by": None,
                                        "selected_user": None,
                                    },
                                )
                            except Exception:
                                logger.exception("[LlaveMX Mobile] Error guardando LlaveMXBlockedLogin")
                        return Response(
                            {"error": "CURP_DUPLICADO_CONTACTE_SOPORTE"},
                            status=status.HTTP_403_FORBIDDEN
                        )

                    # Una cuenta activa → asociar
                    if len(active_users) == 1:
                        user = active_users[0]
                        logger.info(
                            "[LlaveMX Mobile] Asociación por CURP exitosa user_id=%s curp=%s",
                            user.id, curp,
                        )

                    # Una sola cuenta (inactiva)
                    elif len(users_by_curp) == 1:
                        user = users_by_curp[0]
                        logger.info(
                            "[LlaveMX Mobile] Asociación por CURP con cuenta inactiva user_id=%s",
                            user.id,
                        )
                elif curp.upper() == GENERIC_CURP:
                    logger.warning("[LlaveMX Mobile] CURP genérico detectado, no se asocia por CURP.")

            # 3b) Fallback: buscar por email
            if user is None:
                try:
                    user = User.objects.get(email=email)
                    logger.info(f"[LlaveMX Mobile] Usuario encontrado por email: {user.username} ({email})")
                except User.DoesNotExist:
                    pass

            # 3c) Crear usuario nuevo si no se encontró
            if user is None:
                user = User(
                    username=self._unique_username(username),
                    email=email,
                    first_name=user_data.get("nombre", ""),
                    last_name=f"{user_data.get('primerApellido', '')} {user_data.get('segundoApellido', '')}".strip(),
                    is_active=True,
                )
                user.set_unusable_password()
                user.save()
                created = True

                full_name = f"{user_data.get('nombre', '')} {user_data.get('primerApellido', '')}".strip()

                # Crear UserProfile (requerido por Open edX)
                if UserProfile is not None:
                    UserProfile.objects.get_or_create(
                        user=user,
                        defaults={"name": full_name}
                    )

                # Crear Registration y activar (autenticado por LlaveMX = verificado)
                if Registration is not None:
                    reg, _ = Registration.objects.get_or_create(user=user)
                    reg.activate()

                # Crear usuario en el servicio de comentarios/foros
                if create_comments_service_user is not None:
                    try:
                        create_comments_service_user(user)
                    except Exception:
                        logger.warning(f"[LlaveMX Mobile] No se pudo crear usuario en comments service para {user.username}")

                # Preferencia de idioma
                if preferences_api is not None and LANGUAGE_KEY:
                    try:
                        if not preferences_api.has_user_preference(user, LANGUAGE_KEY):
                            preferences_api.set_user_preference(user, LANGUAGE_KEY, get_language() or "es-419")
                    except Exception:
                        logger.warning(f"[LlaveMX Mobile] No se pudo guardar preferencia de idioma para {user.username}")

                # Atributo created_on_site
                if UserAttribute is not None:
                    try:
                        site_name = getattr(request, 'site', None)
                        if site_name:
                            UserAttribute.set_user_attribute(user, "created_on_site", site_name.domain)
                    except Exception:
                        logger.warning(f"[LlaveMX Mobile] No se pudo guardar created_on_site para {user.username}")

                logger.info(f"[LlaveMX Mobile] Usuario creado: {user.username} ({email})")
            else:
                # Asegurar que la cuenta esté activa (autenticado por LlaveMX = verificado)
                if not user.is_active:
                    user.is_active = True
                    user.save(update_fields=["is_active"])
                    logger.info(f"[LlaveMX Mobile] Usuario reactivado: {user.username} ({email})")
                else:
                    logger.info(f"[LlaveMX Mobile] Usuario existente: {user.username} ({email})")
                # Asegurar que exista UserProfile
                if UserProfile is not None:
                    UserProfile.objects.get_or_create(
                        user=user,
                        defaults={"name": f"{user.first_name} {user.last_name}".strip()}
                    )

            # 3d) Guardar/actualizar CURP en ExtraInfo
            if curp and curp.upper() != GENERIC_CURP and ExtraInfo is not None:
                ei, ei_created = ExtraInfo.objects.get_or_create(
                    user=user,
                    defaults={"curp": curp}
                )
                if not ei_created and (not ei.curp or ei.curp.upper() == GENERIC_CURP):
                    ei.curp = curp
                    ei.save(update_fields=["curp"])
                    logger.info(f"[LlaveMX Mobile] CURP actualizado en ExtraInfo para user_id={user.id}")

            # 3e) Vincular con social_auth (UserSocialAuth)
            #     Sin esto, el usuario no queda asociado al provider "llavemx"
            #     y no podrá hacer login vía LlaveMX en la web.
            if UserSocialAuth is not None and uid:
                try:
                    social_extra_data = {
                        "access_token": access_token,
                        "curp": curp,
                        "telefono": user_data.get("telVigente") or "",
                        "fechaNacimiento": user_data.get("fechaNacimiento") or "",
                        "sexo": user_data.get("sexo") or "",
                        "correoVerificado": bool(user_data.get("correoVerificado", False)),
                        "telefonoVerificado": bool(user_data.get("telefonoVerificado", False)),
                        "es_extranjero": bool(user_data.get("esExtranjero", False)),
                    }
                    social_auth, sa_created = UserSocialAuth.objects.update_or_create(
                        user=user,
                        provider="llavemx",
                        uid=str(uid),
                        defaults={"extra_data": json.dumps(social_extra_data)}
                    )
                    if sa_created:
                        logger.info(f"[LlaveMX Mobile] UserSocialAuth creado para user_id={user.id} uid={uid}")
                    else:
                        logger.info(f"[LlaveMX Mobile] UserSocialAuth actualizado para user_id={user.id} uid={uid}")
                except Exception:
                    logger.exception(f"[LlaveMX Mobile] Error al crear/actualizar UserSocialAuth para user_id={user.id}")

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

            # Paso 1: Crear token opaco DOT (base para el JWT)
            dot_token_dict = create_dot_access_token(
                request=request,
                user=user,
                client=client,
                scopes="profile email"
            )

            # Paso 2: Convertir a JWT (la app móvil envía "Authorization: JWT <token>")
            oauth_adapter = adapters.DOTAdapter()
            jwt_token_dict = create_jwt_token_dict(
                dot_token_dict,
                oauth_adapter,
                use_asymmetric_key=True,
            )

            logger.info(f"[LlaveMX Mobile] Login successful for {email}")
            return Response(jwt_token_dict)

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


# Deep link scheme configurado en la app Android
ANDROID_DEEP_LINK_SCHEME = getattr(
    settings,
    "LLAVEMX_ANDROID_DEEP_LINK_SCHEME",
    "mx.aprende.android"
)


class LlaveMxMobileCallback(View):
    """
    Endpoint que recibe el callback de LlaveMX y redirige a la app móvil.
    
    LlaveMX redirige aquí después de la autenticación:
        GET /mobile/callback?code=XXX&state=YYY
    
    Esta vista genera una página que abre la app Android usando deep link:
        mx.aprende.android://oauth/callback?code=XXX&state=YYY
    """
    
    def get(self, request):
        """
        Procesa el callback de LlaveMX y redirige a la app móvil.
        """
        code = request.GET.get("code")
        state = request.GET.get("state")
        error = request.GET.get("error")
        error_description = request.GET.get("error_description", "")
        
        logger.info(f"[LlaveMX Callback] Received - code: {bool(code)}, state: {bool(state)}, error: {error}")
        
        # Construir deep link para la app Android
        if error:
            # Error de LlaveMX
            params = urlencode({"error": error, "error_description": error_description})
            deep_link = f"{ANDROID_DEEP_LINK_SCHEME}://oauth/callback?{params}"
            title = "Error de autenticación"
            message = error_description or error
            button_text = "Volver a la app"
        elif code:
            # Éxito - pasar code y state a la app
            params = urlencode({"code": code, "state": state or ""})
            deep_link = f"{ANDROID_DEEP_LINK_SCHEME}://oauth/callback?{params}"
            title = "Autenticación exitosa"
            message = "Redirigiendo a la aplicación..."
            button_text = "Abrir app"
        else:
            # Sin code ni error
            deep_link = f"{ANDROID_DEEP_LINK_SCHEME}://oauth/callback?error=no_code"
            title = "Error"
            message = "No se recibió código de autorización"
            button_text = "Volver a la app"
        
        # HTML que intenta abrir la app automáticamente
        html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - MéxicoX</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #611232 0%, #8B1538 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 16px;
            padding: 40px;
            max-width: 400px;
            width: 100%;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        .logo {{
            width: 80px;
            height: 80px;
            margin: 0 auto 24px;
            background: #611232;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .logo svg {{
            width: 40px;
            height: 40px;
            fill: white;
        }}
        h1 {{
            color: #333;
            font-size: 24px;
            margin-bottom: 12px;
        }}
        p {{
            color: #666;
            font-size: 16px;
            margin-bottom: 24px;
            line-height: 1.5;
        }}
        .spinner {{
            width: 40px;
            height: 40px;
            border: 4px solid #f3f3f3;
            border-top: 4px solid #611232;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 24px;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .btn {{
            display: inline-block;
            background: #611232;
            color: white;
            padding: 14px 32px;
            border-radius: 8px;
            text-decoration: none;
            font-size: 16px;
            font-weight: 600;
            transition: background 0.3s;
        }}
        .btn:hover {{
            background: #8B1538;
        }}
        .note {{
            margin-top: 20px;
            font-size: 14px;
            color: #999;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
            </svg>
        </div>
        <h1>{title}</h1>
        <p>{message}</p>
        <div class="spinner" id="spinner"></div>
        <a href="{deep_link}" class="btn" id="openApp">{button_text}</a>
        <p class="note">Si la app no se abre automáticamente, presiona el botón.</p>
    </div>
    
    <script>
        // Intentar abrir la app automáticamente
        (function() {{
            var deepLink = "{deep_link}";
            
            // Intentar abrir inmediatamente
            window.location.href = deepLink;
            
            // Ocultar spinner después de un momento
            setTimeout(function() {{
                document.getElementById('spinner').style.display = 'none';
            }}, 2000);
        }})();
    </script>
</body>
</html>
"""
        return HttpResponse(html, content_type="text/html")
