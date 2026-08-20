import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone

from .fields import EncryptedTextField


def generate_token() -> str:
    return secrets.token_hex(32)


def generate_enrollment_code() -> str:
    return secrets.token_urlsafe(16)


class HostGroup(models.Model):
    # views._policy_for()의 그룹-없음 fallback이 이 값들과 어긋나지 않도록 여기서 참조한다
    # (마다 24*3600을 따로 적어두면 둘 중 하나만 바뀌었을 때 조용히 어긋난다 — 유지보수 리뷰 지적).
    DEFAULT_CHECK_INTERVAL_HOURS = 24
    DEFAULT_METRICS_INTERVAL_SECONDS = 30

    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    # RBAC — 비워두면(super user 제외) 이 그룹의 호스트는 아무도 대시보드에서 못 봄.
    # 특정 Django Group에 소속된 사용자만 조회 가능하게 제한한다(Phase 6).
    viewer_group = models.ForeignKey(
        "auth.Group", null=True, blank=True, on_delete=models.SET_NULL,
        help_text="이 그룹에 속한 사용자만 이 HostGroup의 호스트를 볼 수 있음(비워두면 전체 로그인 사용자에게 공개)",
    )
    # 다중 그룹/정책 — 호스트 그룹별 점검·메트릭 주기 차등(Phase 6). enroll/heartbeat
    # 응답에 실려 에이전트가 재등록 없이 하트비트 시점마다 반영한다.
    check_interval_hours = models.PositiveIntegerField(default=DEFAULT_CHECK_INTERVAL_HOURS)
    metrics_interval_seconds = models.PositiveIntegerField(default=DEFAULT_METRICS_INTERVAL_SECONDS)

    def __str__(self) -> str:
        return self.name


class EnrollmentCode(models.Model):
    """1회용 등록 코드. 에이전트는 이 코드를 장기 토큰으로 교환하고, 코드는 그 즉시 소진된다."""

    code = models.CharField(max_length=64, unique=True, default=generate_enrollment_code)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    host = models.ForeignKey(
        "Host", null=True, blank=True, on_delete=models.SET_NULL, related_name="enrollment_codes"
    )

    def __str__(self) -> str:
        return self.code


class Host(models.Model):
    hostname = models.CharField(max_length=255)
    ip = models.GenericIPAddressField(null=True, blank=True)
    os = models.CharField(max_length=50, blank=True)
    distro = models.CharField(max_length=100, blank=True)
    group = models.ForeignKey(
        HostGroup, null=True, blank=True, on_delete=models.SET_NULL, related_name="hosts"
    )
    last_heartbeat_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def rotate_token(self, grace_period=None) -> "AgentToken":
        """기존 활성 토큰(들)에 유예 만료를 걸고 새 토큰을 발급한다 — 신·구 토큰이
        grace_period 동안 공존해, 회전 시점에 이미 요청을 보내고 있던 에이전트가
        끊기지 않는다(design doc 결정: 토큰 회전은 단일 필드로 표현 불가)."""
        if grace_period is None:
            grace_period = timezone.timedelta(hours=24)
        now = timezone.now()
        self.tokens.filter(revoked_at__isnull=True).update(revoked_at=now + grace_period)
        return AgentToken.objects.create(host=self)

    def __str__(self) -> str:
        return self.hostname


class AgentToken(models.Model):
    """Host.agent_token 단일 필드를 대체한다 — 회전 시 신·구 토큰이 잠시 공존해야 하는데
    단일 필드로는 그 기간을 표현할 수 없었다(design doc §5, Phase 6에서 정식 구현)."""

    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="tokens")
    token = models.CharField(max_length=64, unique=True, default=generate_token)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)  # null이면 무기한 유효

    def is_valid(self) -> bool:
        return self.revoked_at is None or self.revoked_at > timezone.now()

    def __str__(self) -> str:
        state = "active" if self.is_valid() else "revoked"
        return f"{self.host.hostname} ({state})"


class CheckRun(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="check_runs")
    profile = models.CharField(max_length=20)  # kisa/docker/cis-linux/isms-p/all
    executed_at = models.DateTimeField()
    pass_count = models.IntegerField(default=0)
    fail_count = models.IntegerField(default=0)
    review_count = models.IntegerField(default=0)
    risk_score = models.IntegerField(default=100)
    # 점검 누락이 "적을수록 좋은 점수"로 위장되지 않도록 실행 완전성을 명시(Codex 교차검증)
    expected_count = models.IntegerField(default=0)
    actual_count = models.IntegerField(default=0)
    # 에이전트가 실행 시작 시 생성해 디스크에 영속화하는 값 — 재전송 시 중복 CheckRun 방지
    run_id = models.CharField(max_length=64, unique=True)

    def __str__(self) -> str:
        return f"{self.host.hostname} {self.profile} {self.executed_at:%Y-%m-%d %H:%M}"


class CheckResult(models.Model):
    STATUS_CHOICES = [("PASS", "PASS"), ("FAIL", "FAIL"), ("REVIEW", "REVIEW")]

    run = models.ForeignKey(CheckRun, on_delete=models.CASCADE, related_name="results")
    code = models.CharField(max_length=20)  # U-01, D-01, CL-01, IS-01 등
    name = models.CharField(max_length=255)
    category = models.CharField(max_length=100, blank=True)
    # 어느 표준(주기반/Docker/CIS Linux/ISMS-P)에서 왔는지 — 원본 JSON 파일명 기준으로
    # 에이전트가 태깅한다(통합 JSON의 한국어 라벨 문자열에 의존하지 않음)
    standard = models.CharField(max_length=20)  # kisa/docker/cis-linux/isms-p
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    # FAIL 항목의 detail에는 실제 설정값(SNMP community string, 파일 권한 등)이 그대로
    # 남을 수 있어 저장 시 암호화한다(plan.md 보안 고려사항, Phase 6에서 구현).
    detail = EncryptedTextField(blank=True)
    reference = models.JSONField(default=dict, blank=True)
    # ISMS-P처럼 다른 표준 결과에서 매핑으로 파생된 판정이면 그 근거 코드 목록을 채운다.
    # 비어있으면 실측 판정, 채워져 있으면 매핑 파생 판정 — 독립 증거로 동등하게 취급하지 않기 위함
    # (Codex 교차검증)
    derived_from_codes = models.JSONField(default=list, blank=True)

    def __str__(self) -> str:
        return f"{self.code} {self.status}"


class MetricSample(models.Model):
    KIND_CHOICES = [("gauge", "gauge"), ("counter", "counter")]

    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="metric_samples")
    metric_type = models.CharField(max_length=20)  # cpu/disk/net
    # cpu: aggregate 또는 core-N / disk: mount point 또는 device 이름 / net: interface 이름
    sub_dimension = models.CharField(max_length=100, blank=True)
    value = models.FloatField()
    unit = models.CharField(max_length=20, blank=True)  # %, bytes, bytes/sec 등
    kind = models.CharField(max_length=10, choices=KIND_CHOICES, default="gauge")
    collected_at = models.DateTimeField()  # 에이전트가 측정한 시각
    received_at = models.DateTimeField(auto_now_add=True)  # 서버가 받은 시각

    class Meta:
        indexes = [
            models.Index(fields=["host", "metric_type", "collected_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.host.hostname} {self.metric_type}:{self.sub_dimension} = {self.value}{self.unit}"


class RemediationProposal(models.Model):
    """실행 경로 없는 티켓/가이드 링크 — 원격 자동 실행은 이 설계에서 완전히 제외한다
    (Codex 교차검증: reference.remediation은 실행 명령이 아닌 안내문이라 원격 실행 시 RCE 위험)."""

    STATUS_CHOICES = [("open", "open"), ("acknowledged", "acknowledged"), ("resolved", "resolved")]

    check_result = models.ForeignKey(
        CheckResult, on_delete=models.CASCADE, related_name="remediation_proposals"
    )
    remediation_text = models.TextField()  # reference.remediation 그대로 — 사람이 읽는 안내문
    # proposals 대시보드가 status__in=["open","acknowledged"]로 매번 필터링하므로 인덱스 필요
    # (성능 리뷰 지적 — 티켓이 쌓일수록 인덱스 없이는 풀 스캔).
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="open", db_index=True)
    acknowledged_by = models.CharField(max_length=150, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    post_check_status = models.CharField(max_length=10, blank=True)

    def __str__(self) -> str:
        return f"{self.check_result.code} ({self.status})"


class DriftEvent(models.Model):
    check_result = models.ForeignKey(CheckResult, on_delete=models.CASCADE, related_name="drift_events")
    previous_status = models.CharField(max_length=10)
    new_status = models.CharField(max_length=10)
    detected_at = models.DateTimeField(auto_now_add=True)
    config_diff = models.TextField(blank=True)
    # 이전 실행과 체크 콘텐츠 버전이 다르면 true — 실제 설정 드리프트인지 체크 스크립트 자체의
    # 변경인지 구분하기 위함(Codex 교차검증, content-version 필드는 Phase 6 이전까지는 항상 False)
    content_version_changed = models.BooleanField(default=False)

    def __str__(self) -> str:
        return f"{self.check_result.code}: {self.previous_status} -> {self.new_status}"


class AlertRule(models.Model):
    """DriftEvent에만 반응한다 — 매 스캔마다 도는 CheckResult가 아니라, 상태가 실제로
    바뀐 순간에만 평가된다. 이게 Codex 교차검증이 지적한 "매 스캔마다 Slack 스팸" 문제를
    별도 dedup 로직 없이 자연스럽게 피하는 방법이다(DriftEvent 자체가 이미 dedup 지점)."""

    SEVERITY_CHOICES = [
        ("fail_only", "FAIL만"),
        ("fail_review", "FAIL + REVIEW"),
    ]
    CHANNEL_CHOICES = [("slack", "Slack")]

    name = models.CharField(max_length=100)
    host_group = models.ForeignKey(
        HostGroup, null=True, blank=True, on_delete=models.SET_NULL,
        help_text="비워두면 전체 호스트에 적용",
    )
    code_pattern = models.CharField(
        max_length=50, blank=True,
        help_text="비워두면 전체 코드. 'U-'처럼 접두사로 쓰면 해당 표준 전체에 매치",
    )
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="fail_only")
    channel = models.CharField(max_length=20, choices=CHANNEL_CHOICES, default="slack")
    slack_webhook_url = models.URLField(blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def matches(self, drift_event: "DriftEvent") -> bool:
        if not self.enabled:
            return False
        if drift_event.new_status not in self._trigger_statuses():
            return False
        result = drift_event.check_result
        if self.host_group_id and result.run.host.group_id != self.host_group_id:
            return False
        if self.code_pattern and not result.code.startswith(self.code_pattern):
            return False
        return True

    def _trigger_statuses(self):
        return {"fail_only": ["FAIL"], "fail_review": ["FAIL", "REVIEW"]}[self.severity]

    def __str__(self) -> str:
        return self.name


class Notification(models.Model):
    STATUS_CHOICES = [("pending", "pending"), ("sent", "sent"), ("failed", "failed")]

    rule = models.ForeignKey(AlertRule, on_delete=models.CASCADE, related_name="notifications")
    drift_event = models.ForeignKey(DriftEvent, on_delete=models.CASCADE, related_name="notifications")
    channel = models.CharField(max_length=20)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    error = models.TextField(blank=True)

    def __str__(self) -> str:
        return f"{self.rule.name} -> {self.channel} ({self.status})"
