from django.urls import path

from . import views

urlpatterns = [
    path("agents/enroll", views.enroll, name="agent-enroll"),
    path("agents/<int:host_id>/results", views.submit_results, name="agent-results"),
    path("agents/<int:host_id>/heartbeat", views.heartbeat, name="agent-heartbeat"),
    path("agents/<int:host_id>/metrics", views.submit_metrics, name="agent-metrics"),
    path("hosts", views.list_hosts, name="host-list"),
    path("hosts/<int:host_id>/history", views.host_history, name="host-history"),
]
