import requests
from celery import shared_task
from django.utils import timezone

from .models import Notification


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def send_notification(self, notification_id: int) -> None:
    notification = Notification.objects.select_related(
        "drift_event__check_result__run__host", "rule"
    ).get(pk=notification_id)

    if notification.channel != "slack":
        notification.status = "failed"
        notification.error = f"지원하지 않는 채널: {notification.channel}"
        notification.save(update_fields=["status", "error"])
        return

    if not notification.rule.slack_webhook_url:
        notification.status = "failed"
        notification.error = "AlertRule에 slack_webhook_url이 설정되지 않음"
        notification.save(update_fields=["status", "error"])
        return

    drift = notification.drift_event
    result = drift.check_result
    host = result.run.host
    text = (
        f"*[{drift.new_status}]* {host.hostname} — {result.code} {result.name}\n"
        f"{drift.previous_status} → {drift.new_status} (감지: {drift.detected_at:%Y-%m-%d %H:%M:%S})\n"
        f"조치 안내: {(result.reference or {}).get('remediation', '없음')}"
    )

    try:
        resp = requests.post(notification.rule.slack_webhook_url, json={"text": text}, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as exc:
        notification.status = "failed"
        notification.error = str(exc)[:500]
        notification.save(update_fields=["status", "error"])
        # 일시적 네트워크 문제일 수 있으니 재시도(최대 3회) — 그래도 계속 실패하면 위 실패
        # 상태로 남아 관리자가 확인할 수 있게 한다(조용히 사라지지 않음).
        raise self.retry(exc=exc)

    notification.status = "sent"
    notification.sent_at = timezone.now()
    notification.save(update_fields=["status", "sent_at"])
