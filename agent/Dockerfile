# 빌드 컨텍스트는 저장소 루트여야 한다 (agent 바이너리뿐 아니라 main.sh + scripts/ 등
# 기존 bash 체커 전체를 이미지에 담아야 shell-out이 실제로 동작한다):
#   docker build -f agent/Dockerfile -t vuln-checker-agent .
#
# plan.md §4-3 배포 매트릭스 참고 — 이 이미지로 커버되는 두 가지 프로파일:
#   1) D-XX 전용(--profile docker): docker.sock만 read-only 마운트하면 됨. 난이도 낮음, 검증됨.
#   2) U-XX/CL-XX 전체(--profile all 등): --net host --pid host + 호스트 절대경로
#      bind mount가 필요하고, bare-metal 대비 점검 정확도가 아직 실측 검증 안 됨
#      (design doc Open Question — 특히 macOS 개발 머신에서는 --net host의 의미 자체가
#      Linux와 달라서 이 이미지로는 검증할 수 없고, 실제 Linux 호스트가 있어야 한다).

FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ .
RUN CGO_ENABLED=0 go build -o /out/vuln-checker-agent .

FROM debian:bookworm-slim

# main.sh(README 명시 의존 도구: stat/awk/grep/find/ss)와 docker/scripts/*가 필요로 하는
# 최소 도구 — 컨테이너 자신의 바이너리로 실행되므로 호스트 도구와 무관하게 갖춰야 한다.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils gawk grep findutils procps iproute2 net-tools \
        docker.io ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/vuln-checker
# 기존 bash 체커 전체(재구현 아님, 그대로 복사) — collector.go가 --main-sh로 이 경로를 가리킨다.
COPY main.sh ./main.sh
COPY scripts/ ./scripts/
COPY docker/ ./docker/
COPY cis-linux/ ./cis-linux/
COPY isms-p/ ./isms-p/
RUN chmod +x main.sh

COPY --from=builder /out/vuln-checker-agent /usr/local/bin/vuln-checker-agent

# 에이전트가 main.sh 실행/서버 통신 외 다른 데 쓰이지 않도록 하는 최소 경계(design doc
# Constraints #6) — 실행 시점의 root-equivalent 자체는 main.sh 특성상 불가피하다.
RUN mkdir -p /opt/vuln-checker/results /opt/vuln-checker/agent-data

ENTRYPOINT ["/usr/local/bin/vuln-checker-agent"]
CMD ["run", "--config", "/opt/vuln-checker/agent-data/agent.json", \
     "--main-sh", "/opt/vuln-checker/main.sh", \
     "--results-dir", "/opt/vuln-checker/results"]
