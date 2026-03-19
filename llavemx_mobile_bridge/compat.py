"""
Imports opcionales de Open edX.

Este módulo centraliza todas las dependencias de Open edX que no existen
fuera del LMS. Si el módulo no está disponible, la variable queda en None
y el código principal lo maneja con un check explícito.
"""

try:
    from openedx.core.djangoapps.oauth_dispatch.api import create_dot_access_token
    from openedx.core.djangoapps.oauth_dispatch.jwt import create_jwt_token_dict
    from openedx.core.djangoapps.oauth_dispatch import adapters
    from oauth2_provider.models import Application
except ImportError:
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

