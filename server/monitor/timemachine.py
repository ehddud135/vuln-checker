"""Compliance time machine — 드리프트 감지 + 조치 티켓 생성.

design doc 결정 그대로: 여기서 만드는 건 실행 경로가 없는 티켓/가이드일 뿐이다.
RemediationProposal.remediation_text는 사람이 읽는 안내문이고, 이걸 파싱해서
실행하는 코드는 이 프로젝트 어디에도 없다(Codex 교차검증: 원격 자동 실행 제거).
"""

from django.utils import timezone

from .models import AlertRule, CheckResult, CheckRun, DriftEvent, Notification, RemediationProposal
from .tasks import send_notification


def _diff_detail(previous_detail: str, new_detail: str) -> str:
    if previous_detail == new_detail:
        return ""
    return f"이전: {previous_detail}\n이후: {new_detail}"


def _open_ticket_for(result: CheckResult) -> None:
    remediation_text = (result.reference or {}).get("remediation", "")
    RemediationProposal.objects.create(check_result=result, remediation_text=remediation_text)


def _resolve_open_tickets(host_id: int, code: str, standard: str, post_check_status: str) -> None:
    RemediationProposal.objects.filter(
        check_result__run__host_id=host_id,
        check_result__code=code,
        check_result__standard=standard,
        status__in=["open", "acknowledged"],
    ).update(status="resolved", resolved_at=timezone.now(), post_check_status=post_check_status)


def _evaluate_alerts(drift_event: DriftEvent, enabled_rules) -> None:
    """DriftEvent 발생 시점(=상태가 실제로 바뀐 순간)에만 평가한다 — 매 스캔마다
    도는 CheckResult 자체를 보는 게 아니라서, 같은 FAIL이 계속 지속돼도 알림이
    반복 발송되지 않는다(Codex 교차검증이 지적한 스팸 문제를 여기서 자연스럽게 피함).

    enabled_rules는 process_run이 한 번만 조회해 넘겨준다 — 드리프트가 여러 건인
    실행에서 매번 같은 쿼리를 반복하지 않기 위함(성능 리뷰 지적).
    """
    for rule in enabled_rules:
        if not rule.matches(drift_event):
            continue
        notification = Notification.objects.create(
            rule=rule, drift_event=drift_event, channel=rule.channel
        )
        send_notification.delay(notification.id)


def process_run(run: CheckRun) -> None:
    """방금 저장된 CheckRun을 이전 실행과 비교해 DriftEvent/RemediationProposal을 만든다.

    첫 실행(비교 대상 없음)은 DriftEvent를 만들지 않는다 — design doc Open Question에서
    이미 결정된 사항(비교 대상 없는 첫 실행이 가짜 드리프트를 만들면 안 됨).
    """
    results = list(run.results.all())

    previous_run = (
        CheckRun.objects.filter(host_id=run.host_id, executed_at__lt=run.executed_at)
        .exclude(pk=run.pk)
        .order_by("-executed_at")
        .first()
    )

    if previous_run is None:
        for r in results:
            if r.status == "FAIL":
                _open_ticket_for(r)
        return

    previous_by_key = {(pr.code, pr.standard): pr for pr in previous_run.results.all()}
    enabled_rules = list(AlertRule.objects.filter(enabled=True))

    for r in results:
        previous = previous_by_key.get((r.code, r.standard))
        if previous is None:
            # 이전 실행엔 없던 새 체크 항목(예: 새 표준이 처음 추가됨) — 드리프트로 볼 기준이
            # 없으므로 DriftEvent는 생략하고, FAIL이면 티켓만 새로 연다.
            if r.status == "FAIL":
                _open_ticket_for(r)
            continue

        if previous.status == r.status:
            continue

        drift_event = DriftEvent.objects.create(
            check_result=r,
            previous_status=previous.status,
            new_status=r.status,
            config_diff=_diff_detail(previous.detail, r.detail),
            content_version_changed=False,  # 체크 콘텐츠 버전 관리는 아직 없음(design doc 참고)
        )
        _evaluate_alerts(drift_event, enabled_rules)

        if r.status == "FAIL":
            _open_ticket_for(r)
        elif r.status == "PASS":
            _resolve_open_tickets(run.host_id, r.code, r.standard, post_check_status="PASS")
