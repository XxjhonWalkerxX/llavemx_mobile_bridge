"""
Tutor plugin para LlaveMX Mobile Bridge.

Inyecta las variables de configuración al LMS de Open edX.
Deben configurarse explícitamente en cada entorno:

    tutor config save \
      --set LLAVEMX_MOBILE_CLIENT_ID="..." \
      --set LLAVEMX_TOKEN_URL="..." \
      --set LLAVEMX_USER_INFO_URL="..." \
      --set LLAVEMX_ANDROID_DEEP_LINK_SCHEME="mx.aprende.android" \
      --set LLAVEMX_IOS_DEEP_LINK_SCHEME="mx.aprende.ios"

    tutor local restart lms
"""
from tutor import hooks

hooks.Filters.ENV_PATCHES.add_item((
    "openedx-lms-common-settings",
    """
# LlaveMX Mobile Bridge — configuración inyectada por Tutor
LLAVEMX_MOBILE_CLIENT_ID         = "{{ LLAVEMX_MOBILE_CLIENT_ID }}"
LLAVEMX_TOKEN_URL                = "{{ LLAVEMX_TOKEN_URL }}"
LLAVEMX_USER_INFO_URL            = "{{ LLAVEMX_USER_INFO_URL }}"
LLAVEMX_ANDROID_DEEP_LINK_SCHEME = "{{ LLAVEMX_ANDROID_DEEP_LINK_SCHEME }}"
LLAVEMX_IOS_DEEP_LINK_SCHEME     = "{{ LLAVEMX_IOS_DEEP_LINK_SCHEME }}"
""",
))
