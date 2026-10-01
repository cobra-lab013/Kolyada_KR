from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("api/stats/", views.stats),
    path("api/check/", views.check),
    path("api/tamper/", views.tamper),
    path("api/restore/", views.restore),
    path("api/reset/", views.reset),
]
