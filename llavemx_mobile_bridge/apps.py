"""
App configuration for LlaveMX Mobile Bridge plugin.

IMPORTANTE: Esta configuración usa el sistema correcto de plugins Ulmo
para que no se muera el LMS al cargar.
"""
from django.apps import AppConfig

try:
    from edx_django_utils.plugins.constants import ProjectType
except ImportError:
    # Fallback para desarrollo local sin Open edX
    class ProjectType:
        LMS = "lms"
        CMS = "cms"


class LlaveMxMobileBridgeConfig(AppConfig):
    """
    Application configuration for LlaveMX Mobile Bridge.
    """
    name = "llavemx_mobile_bridge"
    verbose_name = "LlaveMX Mobile Bridge"

    plugin_app = {
        "url_config": {
            ProjectType.LMS: {
                "namespace": "llavemx_mobile_bridge",
                "relative_path": "urls",
            }
        }
    }
