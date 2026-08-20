from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from . import timemachine
from .auth import authenticate_host
from .models import AgentToken, CheckResult, CheckRun, EnrollmentCode, Host, HostGroup, MetricSample
from .rbac import visible_hosts
from .serializers import (
    CheckRunSerializer,
    EnrollRequestSerializer,
    HostSerializer,
    MetricsSubmitSerializer,
    MetricSampleSerializer,
    ResultsSubmitSerializer,
)


def _compute_risk_score(fail_count: int, review_count: int) -> int:
    """viewer/index.html의 위험도 점수 공식과 동일하게 서버에서 재계산한다."""
    return max(0, 100 - (fail_count * 2 + review_count * 1))


def _authenticate_or_401(request, host_id: int):
    """3개 엔드포인트(submit_results/heartbeat/submit_metrics)가 반복하던
    인증-실패시-401 패턴을 하나로 합친다(유지보수 리뷰 지적 — DRY 위반).
    반환값이 Response면 그대로 리턴하고, Host면 인증 성공."""
    try:
        return authenticate_host(request, host_id)
    except AuthenticationFailed as exc:
        return Response({"detail": str(exc)}, status=status.HTTP_401_UNAUTHORIZED)


def _policy_for(host: Host) -> dict:
    """호스트 그룹별 점검·메트릭 주기 정책(Phase 6) — enroll/heartbeat 응답에 실어
    보내면 에이전트가 재등록 없이 하트비트 시점마다 반영한다."""
    group = host.group
    if group is None:
        return {
            "check_interval_seconds": HostGroup.DEFAULT_CHECK_INTERVAL_HOURS * 3600,
            "metrics_interval_seconds": HostGroup.DEFAULT_METRICS_INTERVAL_SECONDS,
        }
    return {
        "check_interval_seconds": group.check_interval_hours * 3600,
        "metrics_interval_seconds": group.metrics_interval_seconds,
    }


@api_view(["POST"])
def enroll(request):
    serializer = EnrollRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data

    # select_for_update()로 코드 행을 잠그고 검사+소진을 한 트랜잭션 안에서 처리한다 —
    # 잠금 없이 "조회 후 나중에 save"만 하면 동시에 들어온 두 요청이 둘 다 used_at=None을
    # 보고 통과해, 1회용 코드 하나로 Host+AgentToken 쌍이 두 개 만들어질 수 있었다
    # (adversarial review 지적 — P0).
    with transaction.atomic():
        try:
            enrollment_code = EnrollmentCode.objects.select_for_update().get(code=data["code"])
        except EnrollmentCode.DoesNotExist:
            return Response({"detail": "유효하지 않은 등록 코드입니다."}, status=status.HTTP_401_UNAUTHORIZED)

        if enrollment_code.used_at is not None:
            return Response({"detail": "이미 사용된 등록 코드입니다."}, status=status.HTTP_401_UNAUTHORIZED)
        if enrollment_code.expires_at < timezone.now():
            return Response({"detail": "만료된 등록 코드입니다."}, status=status.HTTP_401_UNAUTHORIZED)

        host = Host.objects.create(
            hostname=data["hostname"],
            ip=data.get("ip"),
            os=data.get("os", ""),
            distro=data.get("distro", ""),
        )
        enrollment_code.used_at = timezone.now()
        enrollment_code.host = host
        enrollment_code.save(update_fields=["used_at", "host"])

        agent_token = AgentToken.objects.create(host=host)

    return Response(
        {"host_id": host.id, "token": agent_token.token, **_policy_for(host)},
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
def submit_results(request, host_id: int):
    host = _authenticate_or_401(request, host_id)
    if isinstance(host, Response):
        return host

    serializer = ResultsSubmitSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    data = serializer.validated_data

    # idempotency: 같은 run_id가 이미 있으면 중복 생성하지 않고 기존 결과를 그대로 반환한다
    # (Codex 교차검증: 재전송 시 CheckRun 중복 방지)
    existing = CheckRun.objects.filter(run_id=data["run_id"]).first()
    if existing is not None:
        return Response(CheckRunSerializer(existing).data, status=status.HTTP_200_OK)

    results = data["results"]
    pass_count = sum(1 for r in results if r["status"] == "PASS")
    fail_count = sum(1 for r in results if r["status"] == "FAIL")
    review_count = sum(1 for r in results if r["status"] == "REVIEW")

    # CheckRun 생성과 CheckResult.bulk_create를 하나의 트랜잭션으로 묶는다 — 이전에는
    # 둘이 분리돼 있어서, bulk_create가 실패(예: DB 제약 위반)해도 CheckRun은 이미
    # 커밋된 채로 남았다. 그러면 재시도가 위 idempotency 체크에서 "이미 있음"으로
    # 걸려 200을 반환하면서, 정작 결과는 하나도 저장되지 않은 실행이 "성공"으로
    # 위장되어 영구히 유실됐다(adversarial review 지적 — P0). 트랜잭션으로 묶으면
    # bulk_create가 실패할 때 CheckRun 생성까지 함께 롤백되어, 재시도 시 진짜로
    # 다시 시도된다.
    try:
        with transaction.atomic():
            run = CheckRun.objects.create(
                host=host,
                profile=data["profile"],
                executed_at=data["executed_at"],
                pass_count=pass_count,
                fail_count=fail_count,
                review_count=review_count,
                risk_score=_compute_risk_score(fail_count, review_count),
                expected_count=data.get("expected_count", 0),
                actual_count=len(results),
                run_id=data["run_id"],
            )
            CheckResult.objects.bulk_create(
                [
                    CheckResult(
                        run=run,
                        code=r["code"],
                        name=r["name"],
                        category=r.get("category", ""),
                        standard=r["standard"],
                        status=r["status"],
                        detail=r.get("detail", ""),
                        reference=r.get("reference", {}),
                        derived_from_codes=r.get("derived_from_codes", []),
                    )
                    for r in results
                ]
            )
    except IntegrityError:
        # 경합 상태로 동시에 같은 run_id가 들어온 경우 — 이미 만들어진 것을 반환
        existing = CheckRun.objects.get(run_id=data["run_id"])
        return Response(CheckRunSerializer(existing).data, status=status.HTTP_200_OK)

    # 타임머신 — 이전 실행 대비 드리프트 감지 + 조치 티켓 생성(실행 경로 없음).
    # bulk_create 반환값의 PK 신뢰성이 백엔드마다 달라 안전하게 다시 조회한다.
    timemachine.process_run(run)

    return Response(CheckRunSerializer(run).data, status=status.HTTP_201_CREATED)


@api_view(["POST"])
def heartbeat(request, host_id: int):
    host = _authenticate_or_401(request, host_id)
    if isinstance(host, Response):
        return host

    host.last_heartbeat_at = timezone.now()
    host.save(update_fields=["last_heartbeat_at"])
    return Response({"status": "ok", **_policy_for(host)})


@api_view(["POST"])
def submit_metrics(request, host_id: int):
    host = _authenticate_or_401(request, host_id)
    if isinstance(host, Response):
        return host

    serializer = MetricsSubmitSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    samples = serializer.validated_data["samples"]

    MetricSample.objects.bulk_create(
        [
            MetricSample(
                host=host,
                metric_type=s["metric_type"],
                sub_dimension=s.get("sub_dimension", ""),
                value=s["value"],
                unit=s.get("unit", ""),
                kind=s.get("kind", "gauge"),
                collected_at=s["collected_at"],
            )
            for s in samples
        ]
    )
    return Response({"status": "ok", "count": len(samples)}, status=status.HTTP_201_CREATED)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_hosts(request):
    hosts = visible_hosts(request.user).order_by("hostname")
    return Response(HostSerializer(hosts, many=True).data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def host_history(request, host_id: int):
    try:
        host = visible_hosts(request.user).get(pk=host_id)
    except Host.DoesNotExist:
        return Response({"detail": "존재하지 않는 호스트입니다."}, status=status.HTTP_404_NOT_FOUND)

    runs = host.check_runs.order_by("-executed_at").prefetch_related("results")[:20]
    metrics = host.metric_samples.order_by("-collected_at")[:200]

    return Response(
        {
            "host": HostSerializer(host).data,
            "check_runs": CheckRunSerializer(runs, many=True).data,
            "metric_samples": MetricSampleSerializer(metrics, many=True).data,
        }
    )
