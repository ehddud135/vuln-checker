"""RBAC — HostGroup.viewer_group으로 호스트 가시성을 제한한다(Phase 6).

이 데이터는 사실상 전체 인프라의 취약점 지도라, 열람 권한 자체가 중요 자산이라는
plan.md 보안 고려사항을 실제로 구현한 것. superuser는 항상 전체를 본다.
"""

from django.db.models import Q, QuerySet

from .models import Host


def visible_hosts(user) -> QuerySet[Host]:
    if user.is_superuser:
        return Host.objects.all()

    # 그룹이 아예 없는(미분류) 호스트는 superuser 외에는 보이지 않는다 — enroll()이
    # 새 호스트를 항상 group=None으로 만들기 때문에, 예전 코드(Q(group__isnull=True))는
    # 갓 등록된 모든 호스트를 트리아지 전부터 로그인 사용자 전원에게 공개하는 셈이었다
    # (adversarial review 지적 — P0). HostGroup은 있지만 viewer_group을 일부러 안 걸어둔
    # 경우("공개로 두겠다"는 명시적 선택)는 그대로 전체 공개를 유지한다 — 이건 별개의,
    # 의도된 동작이다.
    user_group_ids = list(user.groups.values_list("id", flat=True))
    return Host.objects.filter(group__isnull=False).filter(
        Q(group__viewer_group__isnull=True) | Q(group__viewer_group_id__in=user_group_ids)
    )
