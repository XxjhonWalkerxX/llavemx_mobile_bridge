"""
Sincronización de usuarios Open edX a partir de datos de LlaveMX.

Este módulo maneja toda la lógica interna de la plataforma:
buscar, crear y actualizar cuentas en Open edX usando los datos
obtenidos de LlaveMX. Es independiente del flujo OAuth2.
"""
import json
import logging
import secrets

from django.contrib.auth import get_user_model
from django.utils.translation import get_language

from .compat import (
    UserProfile,
    Registration,
    create_comments_service_user,
    UserSocialAuth,
    preferences_api,
    LANGUAGE_KEY,
    UserAttribute,
    ExtraInfo,
)

GENERIC_CURP = "XEXX010101HDFXXX04"

logger = logging.getLogger(__name__)
User = get_user_model()


class LlaveMXSyncError(Exception):
    """
    Error durante la sincronización del usuario.
    Contiene el mensaje de error y el HTTP status code a retornar.
    """
    def __init__(self, error, http_status):
        self.error = error
        self.http_status = http_status
        super().__init__(error)


def get_or_create_openedx_user(request, user_data, access_token, uid):
    """
    Busca o crea el usuario en Open edX a partir de los datos de LlaveMX.

    Orden de búsqueda:
    1. Por CURP (ExtraInfo) — alineado con el pipeline web
    2. Por email
    3. Creación de cuenta nueva

    Raises:
        LlaveMXSyncError: si hay un conflicto que impide el login (ej. CURP duplicado).

    Returns:
        User: instancia del usuario activo en Open edX.
    """
    email = user_data.get("correo")
    curp = (user_data.get("curp") or "").strip()
    es_extranjero = bool(user_data.get("esExtranjero", False))

    if es_extranjero and not curp:
        curp = GENERIC_CURP
        logger.info("[LlaveMX] Usuario extranjero sin CURP, asignando genérico.")

    username = curp or user_data.get("login") or (email.split("@")[0] if email else None)

    if not email:
        raise LlaveMXSyncError("No email received from LlaveMX", 400)

    user = _find_by_curp(curp, uid, email)

    if user is None:
        user = _find_by_email(email)

    if user is None:
        user = _create_user(request, user_data, username, email)
    else:
        _ensure_active(user)
        _ensure_profile(user)

    _update_extra_info(user, curp)
    _update_social_auth(user, uid, access_token, curp, user_data)

    return user


# =============================================================
# BÚSQUEDA
# =============================================================

def _find_by_curp(curp, uid, email):
    if not curp or curp.upper() == GENERIC_CURP or ExtraInfo is None:
        return None

    matches = ExtraInfo.objects.filter(curp__iexact=curp).select_related("user")
    if not matches.exists():
        return None

    users_by_curp = [ei.user for ei in matches if ei.user]
    active_users = [u for u in users_by_curp if u.is_active]

    if len(active_users) > 1:
        logger.error(
            "[LlaveMX] CURP duplicado con múltiples cuentas activas. curp=%s users=%s",
            curp, [u.id for u in active_users],
        )
        raise LlaveMXSyncError("CURP_DUPLICADO_CONTACTE_SOPORTE", 403)

    if len(active_users) == 1:
        logger.info("[LlaveMX] Asociación por CURP exitosa. user_id=%s", active_users[0].id)
        return active_users[0]

    if len(users_by_curp) == 1:
        logger.info("[LlaveMX] Asociación por CURP con cuenta inactiva. user_id=%s", users_by_curp[0].id)
        return users_by_curp[0]

    return None


def _find_by_email(email):
    try:
        user = User.objects.get(email=email)
        logger.info("[LlaveMX] Usuario encontrado por email: %s", email)
        return user
    except User.DoesNotExist:
        return None


# =============================================================
# CREACIÓN
# =============================================================

def _create_user(request, user_data, username, email):
    user = User(
        username=_unique_username(username),
        email=email,
        first_name=user_data.get("nombre", ""),
        last_name=f"{user_data.get('primerApellido', '')} {user_data.get('segundoApellido', '')}".strip(),
        is_active=True,
    )
    user.set_password(secrets.token_urlsafe(30))
    user.save()

    full_name = f"{user_data.get('nombre', '')} {user_data.get('primerApellido', '')}".strip()

    if UserProfile is not None:
        UserProfile.objects.get_or_create(user=user, defaults={"name": full_name})

    # bulk_create no dispara post_save signals — evita tareas Celery que
    # desactivarían la cuenta para forzar verificación por email.
    if Registration is not None:
        updated = Registration.objects.filter(user=user).update(activation_key='ACTIVATED')
        if updated == 0:
            Registration.objects.bulk_create(
                [Registration(user=user, activation_key='ACTIVATED')],
                ignore_conflicts=True,
            )

    if create_comments_service_user is not None:
        try:
            create_comments_service_user(user)
        except Exception:
            logger.warning("[LlaveMX] No se pudo crear usuario en comments service. username=%s", user.username)

    if preferences_api is not None and LANGUAGE_KEY:
        try:
            if not preferences_api.has_user_preference(user, LANGUAGE_KEY):
                preferences_api.set_user_preference(user, LANGUAGE_KEY, get_language() or "es-419")
        except Exception:
            logger.warning("[LlaveMX] No se pudo guardar preferencia de idioma. username=%s", user.username)

    if UserAttribute is not None:
        try:
            site = getattr(request, 'site', None)
            if site:
                UserAttribute.set_user_attribute(user, "created_on_site", site.domain)
        except Exception:
            logger.warning("[LlaveMX] No se pudo guardar created_on_site. username=%s", user.username)

    logger.info("[LlaveMX] Usuario creado: %s (%s)", user.username, email)
    return user


# =============================================================
# ACTUALIZACIÓN
# =============================================================

def _ensure_active(user):
    if not user.is_active:
        User.objects.filter(pk=user.pk).update(is_active=True)
        user.is_active = True
        logger.info("[LlaveMX] Cuenta reactivada. username=%s", user.username)


def _ensure_profile(user):
    if UserProfile is not None:
        UserProfile.objects.get_or_create(
            user=user,
            defaults={"name": f"{user.first_name} {user.last_name}".strip()}
        )


def _update_extra_info(user, curp):
    if not curp or curp.upper() == GENERIC_CURP or ExtraInfo is None:
        return
    ei, created = ExtraInfo.objects.get_or_create(user=user, defaults={"curp": curp})
    if not created and (not ei.curp or ei.curp.upper() == GENERIC_CURP):
        ei.curp = curp
        ei.save(update_fields=["curp"])
        logger.info("[LlaveMX] CURP actualizado en ExtraInfo. user_id=%s", user.id)


def _update_social_auth(user, uid, access_token, curp, user_data):
    if UserSocialAuth is None or not uid:
        return
    try:
        extra_data = {
            "access_token": access_token,
            "curp": curp,
            "telefono": user_data.get("telVigente") or "",
            "fechaNacimiento": user_data.get("fechaNacimiento") or "",
            "sexo": user_data.get("sexo") or "",
            "correoVerificado": bool(user_data.get("correoVerificado", False)),
            "telefonoVerificado": bool(user_data.get("telefonoVerificado", False)),
            "es_extranjero": bool(user_data.get("esExtranjero", False)),
        }
        _, created = UserSocialAuth.objects.update_or_create(
            user=user,
            provider="llavemx",
            uid=str(uid),
            defaults={"extra_data": json.dumps(extra_data)},
        )
        action = "creado" if created else "actualizado"
        logger.info("[LlaveMX] UserSocialAuth %s. user_id=%s uid=%s", action, user.id, uid)
    except Exception:
        logger.exception("[LlaveMX] Error al actualizar UserSocialAuth. user_id=%s", user.id)


# =============================================================
# HELPERS
# =============================================================

def _unique_username(base_username):
    if not base_username:
        base_username = "llavemx_user"
    username = base_username
    counter = 1
    while User.objects.filter(username=username).exists():
        username = f"{base_username}_{counter}"
        counter += 1
    return username
