from django.urls import path

from . import dashboard_views

urlpatterns = [
    path("", dashboard_views.host_list, name="host-list-page"),
    path("problems/", dashboard_views.problems, name="problems-page"),
    path("proposals/", dashboard_views.proposals, name="proposals-page"),
    path("drift/", dashboard_views.drift, name="drift-page"),
    path("hosts/<int:host_id>/", dashboard_views.host_detail, name="host-detail-page"),
]
