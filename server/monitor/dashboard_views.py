import json

from django.contrib.auth.decorators import login_required
from django.db.models import Prefetch
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .models import CheckResult, CheckRun, DriftEvent, Host, RemediationProposal
from .rbac import visible_hosts


def _risk_class(score: int) -> str:
    if score >= 80:
        return "risk-good"
    if score >= 50:
        return "risk-warn"
    return "risk-bad"


def _severity_class(status: str) -> str:
    """FAIL/REVIEW/PASS를 Zabbix 스타일 심각도 배지 클래스로 매핑한다."""
    return {"FAIL": "sev-high", "REVIEW": "sev-warning"}.get(status, "sev-none")


def _severity_label(status: str) -> str:
    return {"FAIL": "High", "REVIEW": "Warning"}.get(status, "Not classified")


def _hosts_with_prefetched_runs(user, results_queryset=None):
    """호스트별 latest CheckRun을 N+1 없이 가져온다 — check_runs를 최신순으로 한 번에
    prefetch하고, 파이썬에서 첫 번째(최신)만 골라 쓴다(성능 리뷰 지적 사항)."""
    run_queryset = CheckRun.objects.order_by("-executed_at")
    if results_queryset is not None:
        run_queryset = run_queryset.prefetch_related(Prefetch("results", queryset=results_queryset))
    return visible_hosts(user).prefetch_related(
        Prefetch("check_runs", queryset=run_queryset, to_attr="prefetched_runs")
    )


def _latest_run_for(host: Host):
    if hasattr(host, "prefetched_runs"):
        return host.prefetched_runs[0] if host.prefetched_runs else None
    return host.check_runs.order_by("-executed_at").first()


@login_required
def host_list(request):
    hosts = []
    for host in _hosts_with_prefetched_runs(request.user).order_by("hostname"):
        latest_run = _latest_run_for(host)
        hosts.append(
            {
                "host": host,
                "latest_run": latest_run,
                "risk_class": _risk_class(latest_run.risk_score) if latest_run else "",
                "fail_count": latest_run.fail_count if latest_run else 0,
                "review_count": latest_run.review_count if latest_run else 0,
            }
        )
    return render(request, "monitor/host_list.html", {"hosts": hosts, "nav": "dashboard"})


@login_required
def problems(request):
    """Zabbix의 Problems 뷰 참고 — 각 호스트의 최신 CheckRun에서 FAIL/REVIEW만 모아
    심각도 순(High 먼저)으로 보여준다."""
    rows = []
    non_pass_results = CheckResult.objects.exclude(status="PASS").order_by("code")
    for host in _hosts_with_prefetched_runs(request.user, results_queryset=non_pass_results):
        latest_run = _latest_run_for(host)
        if latest_run is None:
            continue
        for result in latest_run.results.all():
            rows.append(
                {
                    "host": host,
                    "result": result,
                    "sev_class": _severity_class(result.status),
                    "sev_label": _severity_label(result.status),
                    "detected_at": latest_run.executed_at,
                }
            )

    severity_order = {"sev-high": 0, "sev-warning": 1, "sev-none": 2}
    rows.sort(key=lambda r: (severity_order.get(r["sev_class"], 9), r["detected_at"]))

    return render(request, "monitor/problems.html", {"rows": rows, "nav": "problems"})


@login_required
def proposals(request):
    """Fix-First 액션보드 — 열려있는 조치 티켓 목록. 실행 버튼은 없다(design doc 결정):
    remediation_text는 사람이 읽는 안내문일 뿐, 여기서 실행하는 코드패스는 없다."""
    allowed_hosts = visible_hosts(request.user)

    if request.method == "POST":
        # status를 open/acknowledged로 제한 — 이미 resolved된 티켓을 오래된 폼 재제출로
        # 다시 acknowledged로 되돌리면 실제로는 조치 완료된 항목이 대시보드에 다시
        # "열려있음"으로 나타난다(adversarial review 지적).
        proposal = get_object_or_404(
            RemediationProposal,
            pk=request.POST.get("proposal_id"),
            check_result__run__host__in=allowed_hosts,
            status__in=["open", "acknowledged"],
        )
        proposal.status = "acknowledged"
        proposal.acknowledged_by = request.POST.get("acknowledged_by", "").strip() or "operator"
        proposal.acknowledged_at = timezone.now()
        proposal.save(update_fields=["status", "acknowledged_by", "acknowledged_at"])
        return redirect("proposals-page")

    open_tickets = (
        RemediationProposal.objects.filter(
            status__in=["open", "acknowledged"], check_result__run__host__in=allowed_hosts
        )
        .select_related("check_result__run__host")
        .order_by("status", "-check_result__run__executed_at")
    )
    resolved_tickets = (
        RemediationProposal.objects.filter(status="resolved", check_result__run__host__in=allowed_hosts)
        .select_related("check_result__run__host")
        .order_by("-resolved_at")[:20]
    )
    return render(
        request,
        "monitor/proposals.html",
        {"open_tickets": open_tickets, "resolved_tickets": resolved_tickets, "nav": "proposals"},
    )


@login_required
def drift(request):
    """Compliance time machine — 상태 변화(드리프트) 이력. 원격 실행 없음, 관찰 기록일 뿐."""
    events = (
        DriftEvent.objects.filter(check_result__run__host__in=visible_hosts(request.user))
        .select_related("check_result__run__host")
        .order_by("-detected_at")[:100]
    )
    return render(request, "monitor/drift.html", {"events": events, "nav": "drift"})


@login_required
def host_detail(request, host_id: int):
    host = get_object_or_404(visible_hosts(request.user), pk=host_id)
    latest_run = _latest_run_for(host)
    results = latest_run.results.all().order_by("code") if latest_run else []
    # 최신 200개를 가져와야 하므로 내림차순으로 잘라낸 뒤 차트용으로 다시 오름차순 정렬한다
    # — 원래 오름차순+limit이었어서 200개가 넘으면 차트가 영원히 가장 오래된 데이터에
    # 고정되는 버그였다(adversarial review 지적).
    metric_samples = list(reversed(host.metric_samples.order_by("-collected_at")[:200]))
    cpu_samples = [m for m in metric_samples if m.metric_type == "cpu"]

    annotated_results = [
        {"result": r, "sev_class": _severity_class(r.status), "sev_label": _severity_label(r.status)}
        for r in results
    ]

    return render(
        request,
        "monitor/host_detail.html",
        {
            "host": host,
            "latest_run": latest_run,
            "results": annotated_results,
            "risk_class": _risk_class(latest_run.risk_score) if latest_run else "",
            "has_cpu_data": bool(cpu_samples),
            "cpu_labels": json.dumps([m.collected_at.strftime("%H:%M:%S") for m in cpu_samples]),
            "cpu_values": json.dumps([m.value for m in cpu_samples]),
            "nav": "dashboard",
        },
    )
