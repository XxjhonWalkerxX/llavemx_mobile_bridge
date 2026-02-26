"""
URL configuration for LlaveMX Mobile Bridge plugin.
"""
from django.urls import path

from .views import LlaveMxMobileLogin

app_name = "llavemx_mobile_bridge"

urlpatterns = [
    path(
        "api/mobile/llavemx/login/",
        LlaveMxMobileLogin.as_view(),
        name="llavemx_mobile_login"
    ),
]
