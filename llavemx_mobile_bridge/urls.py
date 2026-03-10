"""
URL configuration for LlaveMX Mobile Bridge plugin.
"""
from django.urls import path

from .views import LlaveMxMobileLogin, LlaveMxMobileCallback

app_name = "llavemx_mobile_bridge"

urlpatterns = [
    path(
        "api/mobile/llavemx/login/",
        LlaveMxMobileLogin.as_view(),
        name="llavemx_mobile_login"
    ),
    # Callback que recibe el redirect de LlaveMX y abre la app móvil
    path(
        "mobile/callback",
        LlaveMxMobileCallback.as_view(),
        name="llavemx_mobile_callback"
    ),
]
