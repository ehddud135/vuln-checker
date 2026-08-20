from django.contrib import admin

from .models import (
    AgentToken,
    AlertRule,
    CheckResult,
    CheckRun,
    DriftEvent,
    EnrollmentCode,
    Host,
    HostGroup,
    MetricSample,
    Notification,
    RemediationProposal,
)


@admin.register(HostGroup)
class HostGroupAdmin(admin.ModelAdmin):
    list_display = (
        "name", "description", "viewer_group", "check_interval_hours", "metrics_interval_seconds",
    )


@admin.register(EnrollmentCode)
class EnrollmentCodeAdmin(admin.ModelAdmin):
    list_display = ("code", "created_at", "expires_at", "used_at", "host")
    readonly_fields = ("code", "used_at", "host")


class AgentTokenInline(admin.TabularInline):
    model = AgentToken
    extra = 0
    readonly_fields = ("token", "created_at")
    fields = ("token", "created_at", "revoked_at")


@admin.action(description="선택한 호스트의 토큰 회전(24시간 유예 후 기존 토큰 폐기)")
def rotate_tokens(modeladmin, request, queryset):
    for host in queryset:
        host.rotate_token()


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ("hostname", "os", "distro", "group", "last_heartbeat_at", "created_at")
    inlines = [AgentTokenInline]
    actions = [rotate_tokens]


@admin.register(AgentToken)
class AgentTokenAdmin(admin.ModelAdmin):
    list_display = ("host", "token", "created_at", "revoked_at")
    readonly_fields = ("token",)


class CheckResultInline(admin.TabularInline):
    model = CheckResult
    extra = 0
    fields = ("code", "name", "standard", "status", "derived_from_codes")
    show_change_link = True


@admin.register(CheckRun)
class CheckRunAdmin(admin.ModelAdmin):
    list_display = (
        "host",
        "profile",
        "executed_at",
        "pass_count",
        "fail_count",
        "review_count",
        "risk_score",
        "expected_count",
        "actual_count",
    )
    list_filter = ("profile", "host")
    inlines = [CheckResultInline]


@admin.register(CheckResult)
class CheckResultAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "standard", "status", "run")
    list_filter = ("standard", "status")


@admin.register(MetricSample)
class MetricSampleAdmin(admin.ModelAdmin):
    list_display = ("host", "metric_type", "sub_dimension", "value", "unit", "collected_at")
    list_filter = ("metric_type", "host")


@admin.register(RemediationProposal)
class RemediationProposalAdmin(admin.ModelAdmin):
    list_display = ("check_result", "status", "acknowledged_by", "acknowledged_at")
    list_filter = ("status",)


@admin.register(DriftEvent)
class DriftEventAdmin(admin.ModelAdmin):
    list_display = ("check_result", "previous_status", "new_status", "detected_at", "content_version_changed")


@admin.register(AlertRule)
class AlertRuleAdmin(admin.ModelAdmin):
    list_display = ("name", "host_group", "code_pattern", "severity", "channel", "enabled")
    list_filter = ("enabled", "severity", "channel")


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ("rule", "drift_event", "channel", "status", "created_at", "sent_at")
    list_filter = ("status", "channel")
    readonly_fields = ("rule", "drift_event", "channel", "status", "sent_at", "error")
