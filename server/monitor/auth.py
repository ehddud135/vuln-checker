from rest_framework.exceptions import AuthenticationFailed

from .models import AgentToken, Host


def authenticate_host(request, host_id: int) -> Host:
    """토큰이 URL의 {host_id}에 귀속된 Host와 일치하는지, 그리고 아직 유효한지(회전
    유예기간이 지나지 않았는지) 검증한다.

    토큰 하나로 다른 호스트의 결과를 올리는 경로를 막기 위한 필수 검증
    (Codex 교차검증: 에이전트 인증 경계). Phase 6에서 Host.agent_token 단일 필드를
    AgentToken 테이블로 교체 — 회전 시 신·구 토큰이 잠시 공존해야 하기 때문이다.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Token "):
        raise AuthenticationFailed("Authorization: Token <token> 헤더가 필요합니다.")
    token = auth_header[len("Token "):].strip()
    if not token:
        raise AuthenticationFailed("빈 토큰입니다.")

    try:
        agent_token = AgentToken.objects.select_related("host").get(token=token, host_id=host_id)
    except AgentToken.DoesNotExist:
        # 존재하지 않는 호스트인지, 토큰이 다른 호스트 것인지 구분하지 않는다 —
        # 어느 쪽이든 클라이언트에 줄 수 있는 정보는 "인증 실패"뿐이어야 한다.
        raise AuthenticationFailed("토큰이 이 호스트에 귀속되지 않습니다.")

    if not agent_token.is_valid():
        raise AuthenticationFailed("폐기된 토큰입니다 — 새 토큰으로 재등록하세요.")

    return agent_token.host
