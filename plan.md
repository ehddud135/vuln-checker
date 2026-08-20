# vuln-checker 모니터링 플랫폼화 계획 (Go Agent + Django Server, Zabbix UX 모방)

> 이전 버전은 "실제 Zabbix에 연동"하는 안이었으나, 방향을 바꿔 **Zabbix 같은 UI/UX를 가진 독자 플랫폼을 직접 구축**하는 쪽으로 정리한다. 서버는 Python/Django, 각 대상 서버에는 Go로 작성한 에이전트를 배포한다.

## 0. 결론부터

- **서버: Django + Django REST Framework(DRF) + PostgreSQL.** Django admin이 "다중 호스트 인벤토리"(호스트 목록/그룹/상태 추적)를 거의 그대로 제공하고, ORM으로 점검 이력을 쌓기 쉽다.
- **에이전트: Go 단일 바이너리.** 단, 72(U)+68(D)+44(CL)+17(IS)개 점검 로직은 **Go로 재작성하지 않고 기존 bash 스크립트(`main.sh` 등)를 그대로 실행(shell-out)**해서 결과 JSON만 받아 파싱 후 서버로 전송. 이 로직은 최근에도 오탐/과탐 수정이 여러 차례 있었던 검증된 자산이므로 재구현 리스크를 피한다.
- **통신: 주기 실행(cron/systemd timer) 후 HTTPS REST POST로 결과 push.** Zabbix trapper와 동일한 사고방식 — 점검이 무겁고 느리므로 서버가 pull하는 구조보다 에이전트가 끝난 뒤 밀어넣는 구조가 맞다.
- **진짜 공수가 드는 곳은 UI가 아니라 "에이전트 인증/등록"과 "알림·트리거 엔진"** — 이 두 가지가 이번 계획에서 가장 신경 써야 할 부분이다.
- **배포는 Docker 형태(서버: docker-compose, 에이전트: Docker 이미지)를 기본 제공.** 단, 에이전트를 컨테이너로 돌리면 호스트의 실제 계정/서비스/커널 파라미터를 봐야 하는 U-XX 점검 특성상 볼륨 마운트·호스트 네임스페이스 설계가 필요하다 — 이 부분이 이번 변경에서 새로 생긴 가장 큰 리스크다(§4 참고).

---

## 1. 왜 이 방향으로 바꿨나

| 이전 안 (실제 Zabbix 연동) | 이번 안 (독자 플랫폼) |
|---|---|
| 기존 Zabbix 인프라 재사용, 알림/트리거/권한 관리 공짜로 얻음 | 이 도구 전용 UX 설계 가능, Zabbix 버전/설정에 종속 안 됨 |
| Zabbix Host/Item/Trigger 모델에 맞춰 데이터를 욱여넣어야 함 | 데이터 모델(코드/카테고리/기준/위험도 점수)을 우리 필요에 맞게 설계 가능 |
| 조직에 Zabbix가 이미 있어야 이득이 큼 | 배포 대상에 요구사항이 적음(Django 서버 하나 + Go 바이너리) — 오픈소스 프로젝트로서 배포하기엔 이쪽이 자연스러움 |
| 알림/이력저장/RBAC를 Zabbix가 이미 해결 | 알림/이력저장/RBAC를 전부 새로 만들어야 함 (가장 큰 비용) |

이 프로젝트가 GitHub Pages로 뷰어를 공개 배포하는 오픈소스 도구라는 점을 고려하면, "설치 전제조건(Zabbix 서버)이 없는" 독자 플랫폼이 배포 장벽이 낮다는 것도 이 방향의 근거다.

---

## 2. 전체 아키텍처

```
[대상 서버 1..N]                              [중앙 서버]
┌────────────────────┐                  ┌─────────────────────────────┐
│ Go Agent            │   HTTPS POST     │ Django + DRF                │
│  - cron/systemd      │ ───────────────▶│  - /api/agents/enroll        │
│    timer로 주기 실행 │   (결과 push)    │  - /api/agents/{id}/results  │
│  - main.sh --profile │                  │  - /api/agents/{id}/heartbeat│
│    all 실행(shell-out)│                  ├─────────────────────────────┤
│  - 결과 JSON 파싱     │                  │ PostgreSQL                   │
│  - 서버로 전송        │                  │  - Host, HostGroup            │
└────────────────────┘                  │  - CheckRun, CheckResult      │
                                          │  - AlertRule, Notification    │
                                          ├─────────────────────────────┤
                                          │ Alerting Engine (Django task) │
                                          │  - FAIL/REVIEW 발생 시 규칙 평가│
                                          │  - Slack/이메일 발송           │
                                          ├─────────────────────────────┤
                                          │ Web UI (Zabbix 스타일)        │
                                          │  - 호스트 목록/그룹            │
                                          │  - 점검 항목별 상태·이력 그래프 │
                                          │  - 위험도 점수 대시보드        │
                                          └─────────────────────────────┘
```

기존 `results/*.json` 스키마(`code`, `name`, `category`, `status`, `detail`, `reference.*`)는 그대로 재사용한다. Go 에이전트는 이 JSON을 그대로 API에 실어 보내고, 뷰어(`viewer/index.html`)의 위험도 점수 로직도 서버 쪽에서 동일하게 재구현해 대시보드에 노출한다.

**수집 계약 (Codex 교차검증 반영 — 실제 출력 형태와 모델 불일치 수정):** `main.sh --profile all`은 개별 표준별 파일(`result_*.json`, `docker_result_*.json`, `cis_linux_result_*.json`, `isms_p_result_*.json`)과, 2개 이상 기준이 실행된 경우에만 추가로 생성되는 통합 파일(`result_all_*.json`)을 만든다. 개별 파일에는 `standard` 필드가 없고 통합 파일의 `standard`는 한국어 라벨 문자열이다. 에이전트는 **통합 파일이 아니라 개별 파일을 각각 읽고, 어느 파일에서 읽었는지(파일명)로 `CheckResult.standard`를 직접 태깅**한다 — JSON 콘텐츠의 `standard` 필드에 의존하지 않는다. `CheckRun`은 한 번의 `main.sh` 실행을 나타내는 1행이고, 그 안에 여러 표준의 `CheckResult`가 섞여 들어간다. **ISMS-P(IS-XX)는 U-XX 결과에서 매핑으로 파생된 판정이므로 다른 표준과 동등한 독립 증거로 취급하지 않는다** — `CheckResult`에 `derived_from_codes`(매핑된 U-XX 코드 목록, ISMS-P가 아니면 빈 값) 필드를 추가해 UI에서 "실측 판정"과 "매핑 파생 판정"을 시각적으로 구분한다.

---

## 3. 컴포넌트별 설계

### 3-1. Go Agent

- **역할**: 스케줄 실행 → 기존 bash 점검 스크립트 호출 / 인프라 메트릭 수집 → 결과 JSON 파싱 → 서버 전송 → 하트비트 전송. 점검 로직 자체는 구현하지 않는다.
- **배포 형태**: 단일 정적 바이너리 + 설정 파일(서버 주소, 등록 토큰, 실행 주기, 프로파일). systemd timer 또는 자체 내장 스케줄러(Go의 `time.Ticker`) 중 택 1 — 후자가 배포 단순화(systemd 유닛 파일 관리 불필요)에 유리.
- **스케줄러는 이중 주기다 — 하나로 합치지 않는다**: 메트릭(CPU/디스크/네트워크)은 "살아있는 대시보드"의 핵심 가치이므로 초~분 단위 티커로 수집하고, 전체 취약점 점검(`main.sh --profile all`, root 권한, 수 분 소요)은 하루~주 1회 수준의 별도 티커로 실행한다. 하나의 스케줄로 묶으면 메트릭이 점검 주기만큼만 갱신되어 실시간성이 무력화된다.
- **필수 기능**:
  - 최초 실행 시 서버에 자기 자신을 등록(enrollment) — 호스트명/OS/IP 등 메타데이터 전송, 서버가 발급한 에이전트 토큰을 로컬에 저장
  - 주기적으로 `sudo main.sh --profile all` 실행. `main.sh`는 shadow 파일·systemctl·ss·docker 소켓 등 ~200개 체크에 걸쳐 광범위한 OS 가시성이 필요하므로, 명령 단위 sudoers 화이트리스트는 실질적인 최소권한이 아니다(결정됨 — 오피스아워 설계 문서 Premise 6). 에이전트는 점검 실행 시점에 root-equivalent 권한을 갖는 것을 그대로 인정하고, 보안 경계는 전용 서비스 계정·최소 네트워크 egress·바이너리 무결성 검증으로 옮긴다.
  - 실행 실패/타임아웃 처리, 재시도
  - 결과 전송 실패 시 로컬 큐잉(네트워크 단절 대비) 후 재전송. **재시도 idempotency는 "키 하나"로 끝나지 않는다(Codex 교차검증 반영)**: 실행 시작 시점에 run ID를 생성해 디스크에 영속화(같은 결과 파일을 다시 읽어 새 키를 만들면 중복 방지가 깨짐), 배치 전체(CheckRun + 그 안의 모든 CheckResult)를 원자적으로 저장, 부분 실패 시 처리 방식, 큐 용량·보존 기간·초과 시 드롭 정책까지 설계에 포함.
  - 하트비트(heartbeat) — 점검 결과와 별개로 "에이전트가 살아있다"는 신호를 주기적으로 전송 (Zabbix의 nodata 트리거에 대응하는 기능)

### 3-2. Django Server

- **API (DRF)**:
  - `POST /api/agents/enroll` — 신규 호스트 등록, 토큰 발급
  - `POST /api/agents/{id}/results` — 점검 결과 업로드 (기존 JSON 스키마 그대로 body에)
  - `POST /api/agents/{id}/heartbeat` — 생사 신호
  - `GET /api/hosts`, `/api/hosts/{id}/history` — UI가 조회하는 읽기 API
- **인증**: 호스트별 발급 토큰(DRF TokenAuthentication 또는 API Key) — Zabbix의 PSK 개념과 동일한 목적. HTTPS(TLS)는 필수. mTLS는 사이드 프로젝트 규모의 위협 모델 대비 과잉 스펙(gold-plating)이므로 MVP에서는 채택하지 않고, 실제 다중 조직 운영 단계에 들어갈 때만 재검토한다.
- **Admin**: Django admin을 호스트/그룹 관리, 알림 규칙 관리에 그대로 활용 — 별도 관리자 화면을 초기에 새로 만들지 않아도 됨.
- **비동기 처리**: 알림 발송, 대량 결과 저장은 Celery(+ Redis) 같은 백그라운드 큐를 초기부터 고려 (요청-응답 안에서 Slack 전송까지 하면 API 응답이 느려짐).

### 3-3. 데이터 모델 (초안)

| 모델 | 주요 필드 |
|------|-----------|
| `HostGroup` | name, description |
| `Host` | hostname, ip, os, distro, group(FK), agent_token, last_heartbeat_at |
| `CheckRun` | host(FK), profile(kisa/docker/cis-linux/isms-p/all), executed_at, pass_count, fail_count, review_count, risk_score, expected_count(해당 프로파일의 전체 항목 수), actual_count(실제 기록된 항목 수) — 누락된 점검이 "적을수록 좋은 점수"로 위장되지 않도록 실행 완전성을 명시 |
| `CheckResult` | run(FK), code(U-01 등), name, category, standard, status(PASS/FAIL/REVIEW), detail(마스킹 옵션), reference(JSON) |
| `AlertRule` | 대상 그룹/코드 패턴, 조건(FAIL 발생 시 등), 채널(Slack/Email), severity |
| `Notification` | rule(FK), check_result(FK), sent_at, channel, status |
| (Phase 4 설계 시 확장 필요) | `AlertRule`+`Notification`만으로는 발송만 되고 문제 생명주기(같은 FAIL 중복 억제, PASS 전환 시 recovery, 사람의 acknowledge/mute, 예외 만료, 판정 기준 변경 시 재평가)가 없음 — 매 스캔마다 Slack 스팸이거나 중요한 재발을 놓칠 수 있음(Codex 교차검증 반영). Phase 4 착수 시 `Problem`/`Incident` 유사 상태 모델을 먼저 설계할 것. |
| `MetricSample` | host(FK), metric_type(cpu/disk/net), **sub_dimension**(예: cpu는 aggregate/core-N, disk는 mount point 또는 device 이름, net은 interface 이름), value, **unit**(%, bytes, bytes/sec 등), **kind**(gauge 순간값 vs counter 누적값 — disk used/free는 gauge, network rx/tx는 보통 counter라 rate 계산이 별도 필요), collected_at(에이전트가 측정한 시각), received_at(서버가 받은 시각) — CPU aggregate/per-core, 디스크 mount/device, 네트워크 interface/rx-tx를 구분 못 하면 "테이블 추가"가 아니라 무의미한 blob이 된다(Codex 교차검증 반영) |

### 3-4. Web UI (Zabbix 스타일)

- Zabbix의 익숙한 정보 구조(호스트 목록 → 호스트 상세 → 아이템별 이력 그래프, 문제(Problem) 목록, 심각도별 색상)를 참고하되 이 도구 전용 개념(위험도 점수, 조치 방법, ISMS-P 매핑)을 얹는다.
- 초기 버전은 Django 템플릿 + Chart.js 정도로 빠르게, 이후 필요하면 별도 SPA(React 등) + DRF API 소비 구조로 분리.
- 기존 `viewer/index.html`의 Fix-First 액션보드, 비교 분석(diff), 위험도 점수 로직은 그대로 이식 가능 — 새로 발명할 필요 없음.
- **하이브리드 결정(구현 완료 ✅)**: 메트릭 시계열 그래프는 Grafana로 분리했다. 호스트 목록/Problems/조치 워크플로(Django, 이 절 위 내용)는 그대로 유지 — Grafana는 읽기 전용 시각화만 잘하고, 클릭해서 상태를 바꾸는 인터랙티브 워크플로에는 안 맞기 때문에 전체를 Grafana로 옮기지 않았다.
  - `grafana/provisioning/datasources/postgres.yml` — Django와 같은 Postgres를 `grafana_reader`(읽기 전용 롤, `grafana/create_grafana_reader.sql`로 생성)로 조회.
  - `grafana/provisioning/dashboards/metrics.json` — CPU 사용률(호스트별) + 위험도 점수 추이 패널, `$host` 템플릿 변수.
  - `docker-compose.yml`에 `grafana` 서비스 추가(포트 3000). 실제 데이터로 쿼리·대시보드 렌더링까지 확인함.
- **타임머신(DriftEvent/RemediationProposal) 구현 완료 ✅**: `server/monitor/timemachine.py` — 새 CheckRun이 들어올 때마다 직전 실행과 (code, standard) 기준으로 비교해 상태 변화 시 `DriftEvent` 생성. 첫 실행(비교 대상 없음)은 드리프트로 안 만듦(Open Question 해결). FAIL로 드리프트하면 `RemediationProposal` 티켓을 자동으로 열고, 같은 코드가 나중에 PASS로 돌아오면 열려있던 티켓을 자동으로 `resolved`(post_check_status=PASS) 처리.
  - **원격 실행 없음이 실제로 유지됨** — `remediation_text`는 문자열로 저장·표시만 되고, 이걸 파싱해서 실행하는 코드는 프로젝트 어디에도 없음(Codex 교차검증 결정 그대로 구현).
  - `/proposals/` — Fix-First 액션보드. 조치 안내문 복사 버튼 + "확인"(acknowledge) 폼(실행 버튼 아님, 담당자 이름만 기록).
  - `/drift/` — 상태 변화 타임라인. `content_version_changed`가 False일 때만 "설정 드리프트로 추정" 표시(체크 콘텐츠 버전 관리 자체는 아직 없어 항상 False — Phase 6 예정 항목).
  - 실제로 PASS→FAIL→PASS 시퀀스를 주입해 DriftEvent 2건 생성 + 티켓 자동 open→resolved 전체 사이클과, acknowledge 폼(CSRF 포함) 제출까지 end-to-end 검증함.

---

## 4. Docker 배포 형태

두 컴포넌트(서버/에이전트)는 Docker와의 궁합이 완전히 다르다. 서버는 흔한 웹앱 컨테이너화라 어렵지 않지만, 에이전트는 "컨테이너 안에서 호스트를 점검한다"는 근본적인 긴장이 있다.

### 4-1. 서버 — 표준적인 docker-compose 구성 (구현 완료 ✅)

**현재 구현된 구성** (`docker-compose.yml`, 저장소 루트):

```
docker-compose.yml
├── web        (Django + gunicorn, server/Dockerfile)
└── db         (postgres:17-alpine)
```

`redis`/`worker`(Celery 알림 엔진)/`nginx`는 아직 추가하지 않았다 — Phase 4(알림 엔진)에서 실제 Celery 코드가 생기기 전까지는 할 일 없는 컨테이너를 미리 띄우지 않는다(빈 인프라 먼저 짓지 않기). `entrypoint.sh`가 컨테이너 시작 시 `migrate` + `collectstatic`을 자동 실행한 뒤 gunicorn을 띄운다. `POSTGRES_HOST` 환경변수 유무로 Postgres(컨테이너)/sqlite(로컬 `manage.py runserver`)를 자동 전환하도록 `settings.py`를 구성해, 로컬 개발과 컨테이너 배포가 같은 코드베이스를 그대로 쓴다.

`docker compose up -d` + `docker compose exec web python manage.py shell`로 실제 Postgres에 enroll→hosts 조회까지 end-to-end 검증 완료(podman/docker 모두 호환).

- GHCR 자동 빌드(GitHub Actions)는 아직 없음 — 로컬 `docker compose build`만 확인된 상태, CI 파이프라인은 별도 작업.
- 환경변수는 `.env.example`(저장소에 커밋) → `.env`(gitignore, 로컬에서 값 채움)로 주입. Slack Webhook 등은 Phase 4에서 추가.

### 4-2. 에이전트 — 호스트 접근이 핵심 과제

기존 U-XX/CL-XX 점검은 `/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config`, `crontab`, `systemctl`/`service` 상태, `sysctl` 값 등 **호스트의 실제 상태**를 봐야 한다. 에이전트를 그냥 `docker run`으로 띄우면 컨테이너 자신의 격리된 뷰만 보게 되어 점검 자체가 무의미해진다. 이 프로젝트에 이미 있는 **Docker CIS Benchmark 점검(D-XX)이 참고한 `docker-bench-security`가 정확히 같은 문제를 풀어놓은 선례**이므로 그 패턴을 그대로 가져온다:

```bash
# 주의: /hostfs 접두사 마운트가 아니라 호스트와 "동일한 절대경로"에 마운트한다
# (design doc Constraints에서 확정 — 체크 스크립트가 /etc/passwd 등 절대경로를
# 그대로 참조하므로, 컨테이너 안에서도 같은 경로로 보여야 스크립트 수정이 불필요함)
docker run -d \
  --net host --pid host --userns host --cap-add audit_control \
  -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /usr/lib/systemd:/usr/lib/systemd:ro \
  -e VC_SERVER_URL=... -e VC_AGENT_TOKEN=... \
  ghcr.io/<org>/vuln-checker-agent
```

**참고(Codex 교차검증)**: `--pid host`만으로는 `systemctl`이 실제로 필요로 하는 호스트 systemd/DBus 소켓 접근까지 해결되지 않을 수 있음 — Phase 5에서 U-XX 전체 점검 컨테이너 검증 시 systemctl 기반 체크(U-38, U-52 등)가 실제로 정상 동작하는지 개별 확인 필요(단순 PID 네임스페이스 공유로 끝나지 않을 가능성).

- `--pid host` : `ps`/`systemctl` 기반 점검(U-38 DoS 취약 서비스, U-52 Telnet 등)이 실제 호스트 프로세스를 보게 함
- `--net host` : `ss`/`netstat` 기반 점검(U-56 FTP 접근 제어 등)이 호스트 네트워크 상태를 보게 함
- `/etc`, `/var/lib` 등 읽기 전용 마운트 : 파일 권한·설정 점검 대상 경로 확보. 기존 bash 체크가 `/etc/passwd` 같은 절대경로를 그대로 참조하므로, 위 코드처럼 **컨테이너 안에서도 호스트와 동일한 절대경로**에 bind mount한다 — 체크 스크립트에 `$VC_HOST_ROOT` 접두사를 넣는 리팩터링(기존 116개 체크 파일 전체 수정 필요)은 "점검 로직 재구현 금지" 제약을 위반하므로 채택하지 않는다(결정됨).
- **한계**: `--privileged` 없이도 대부분 되지만, `/etc/shadow` 읽기(U-18) 등 일부는 root 컨테이너 + 파일 마운트로 충분히 해결 가능. 다만 **완전한 동등성은 보장 안 됨** — 예를 들어 커널 모듈 점검, SELinux/AppArmor 상태처럼 네임스페이스를 넘어서는 항목은 컨테이너에서 왜곡될 수 있어 개별 검증이 필요하다.
- **대안**: 배포 편의성보다 정확도가 우선인 조직에는 "에이전트는 호스트에 직접 설치되는 단일 바이너리(systemd 서비스)"를 기본으로 안내하고, Docker 이미지는 "컨테이너 환경에서 Docker 데몬(D-XX)만 점검하는 경량 모드"로 용도를 분리하는 것도 고려할 만하다.

### 4-3. 배포 매트릭스 정리

| 컴포넌트 | Docker 배포 | 난이도 | 비고 |
|---|---|---|---|
| Django 서버 | ✅ 권장 | 낮음 | 표준 웹앱 컨테이너화 |
| Go 에이전트 (U-XX/CL-XX 전체 점검) | ⚠️ 가능하나 host 네임스페이스·마운트 필요 | 높음 | 정확도 검증 필요, bare-metal 설치가 더 안전한 대안 |
| Go 에이전트 (D-XX Docker 전용 점검) | ✅ 적합 | 낮음 | 원래 Docker 소켓·데몬을 보는 점검이라 컨테이너 배포와 목적이 자연스럽게 맞음 |

---

## 5. 보안 고려사항 (이전 계획에서 이어지는 원칙)

- FAIL 항목의 `detail`에는 실제 설정값(SNMP community string, 파일 권한 등)이 포함될 수 있음 — 서버 DB에 평문 저장 시 DB 자체가 공격 대상이 된다는 점을 감안, 저장 시 암호화(at-rest) 또는 마스킹 옵션 필요.
- 에이전트 ↔ 서버 통신은 HTTPS 필수. 토큰 회전(rotation)/폐기(revoke)는 MVP 범위 밖 — Host 모델은 Phase 1~5에서 `agent_token` 단일 필드로 충분하고, Phase 6(운영 강화)에서 토큰 이력 테이블과 함께 정식 설계한다(단일 필드로는 회전 시 신·구 토큰 공존 기간을 표현할 수 없음).
- 에이전트가 `sudo main.sh`를 실행해야 하므로 점검 실행 시점엔 root-equivalent 권한이 불가피함(결정됨). 대신 에이전트 바이너리 자체의 공격 표면을 줄이는 쪽에 최소 권한 원칙을 적용 — 전용 서비스 계정, main.sh 실행 및 서버 통신 외 다른 네트워크 egress/명령 실행 차단, 바이너리 무결성 검증.
- 관리자(Django admin/UI) 접근 권한도 RBAC로 분리 — 이 데이터가 사실상 전체 인프라의 취약점 지도이므로 열람 권한 자체가 중요 자산.
- **에이전트 컨테이너에 `/var/run/docker.sock`을 마운트하면 사실상 호스트 root 권한과 동등한 접근을 컨테이너에 주는 것** — Docker 소켓 마운트 자체가 D-XX 점검(예: 소켓 권한 점검 항목)이 지적하는 위험 패턴과 정확히 같은 형태이므로, 꼭 필요한 경우(D-XX 점검용)로만 한정하고 read-only 마운트를 강제.

---

## 6. 로드맵

1. **Phase 1 — 스캐폴딩**: Django 프로젝트 생성(DRF, Postgres 연결), `Host`/`CheckRun`/`CheckResult` 모델 + admin 등록. Go 에이전트는 최소 기능(등록 → 기존 JSON 파일 읽어서 POST)만 구현해 로컬 1대 서버로 end-to-end 확인. (아직 Docker화 이전, bare-metal/venv 기준)
2. **Phase 2 — 실사용 에이전트** (구현 완료 ✅): 스케줄러(이중 티커)·하트비트·`main.sh` 실행은 Phase 1에서 이미 구현. 이번에 추가:
   - `agent/internal/queue` — 디스크 기반 재전송 큐. 서버 다운 시 `PostResults` 실패한 페이로드를 파일로 영속화(임시파일+rename으로 원자적 쓰기), 하트비트 성공 시점마다 자동 재시도, 용량(200개)·보존기간(7일) 초과분은 명시적으로 로그 남기고 폐기.
   - 실제로 서버 컨테이너를 내렸다 올려서 검증: 큐잉 → 재기동 후 자동 flush → 유실도 중복도 없음(idempotency는 run_id가 실행 시작 시점에 이미 고정되므로 그대로 유지).
   - 호스트 3대를 동시에 등록해 인벤토리(호스트 목록/Problems/Grafana `$host` 변수) 전부에서 정상 집계 확인.
3. **Phase 3 — UI 고도화 + 타임머신** (Codex 교차검증 반영 — 알림 엔진보다 먼저): 기존 뷰어의 위험도 점수/비교 분석/조치 가이드(티켓/가이드 링크, 원격 실행 없음)를 Django UI에 이식, `DriftEvent`/`RemediationProposal` 스키마 구현, Zabbix 스타일 대시보드(Problem 목록, 그래프) 완성. 이 프로젝트의 차별점(점검 콘텐츠 + 이력 UX)을 범용 알림 인프라보다 먼저 검증한다.
   - ✅ **최소 버전 구현 완료**: 호스트 목록 페이지(`/`, 위험도 점수 배지·최근 점검 요약) + 호스트 상세 페이지(`/hosts/<id>/`, CheckResult 목록 + Chart.js CPU 그래프). Django 템플릿 기반, 실제 DB 데이터로 렌더링 검증됨.
   - ⬜ 아직 없음: 비교 분석(diff), `DriftEvent`/`RemediationProposal` UI, Problem 목록, 심각도 색상 체계, Fix-First 액션보드 이식.
4. **Phase 4 — 알림 엔진** (구현 완료 ✅): `AlertRule`(host_group/code_pattern/severity/channel) + `Notification` 모델 신설(이전엔 plan.md 표에만 있었고 실제 모델은 없었음). Celery(`config/celery.py`) + Redis로 비동기 발송 — `REDIS_URL` 없으면 eager(동기) 모드로 자동 전환해 로컬 dev는 Redis 없이도 그대로 동작.
   - **알림은 DriftEvent에만 반응한다** — 매 스캔의 CheckResult가 아니라 상태가 실제로 바뀐 순간(`_evaluate_alerts`)에만 평가하므로, Codex 교차검증이 지적한 "지속되는 FAIL마다 Slack 스팸" 문제를 별도 dedup 로직 없이 피함. 첫 실행이나 새로 나타난 코드는 DriftEvent가 없어 알림도 안 나감(티켓은 생성됨) — 의도된 트레이드오프.
   - `docker-compose.yml`에 `redis`+`worker` 서비스 추가(entrypoint.sh를 web/worker 겸용으로 수정 — migrate는 web에서만).
   - 실제로 검증: PASS→FAIL 드리프트 주입 → Notification 생성 → **별도 worker 컨테이너**가 Redis를 통해 태스크를 실제로 받아 처리(즉시 실행이 아님, 진짜 비동기) → 성공 시 `sent`, 웹훅이 500을 반환하는 실패 케이스는 재시도 후 `failed` + 에러 메시지 보존(조용히 사라지지 않음) 둘 다 확인.
5. **Phase 5 — Docker 패키징** (부분 구현 완료 ⚠️): 서버 `docker-compose.yml`은 Phase 1~4에서 이미 완성(web/db/redis/worker/grafana). 이번에 추가:
   - `agent/Dockerfile` — 빌드 컨텍스트는 저장소 루트(agent 바이너리 + main.sh/scripts/docker/cis-linux/isms-p 전체를 이미지에 담음). 런타임은 debian:bookworm-slim + bash/gawk/grep/findutils/procps/iproute2/net-tools/docker.io(README 명시 의존 도구 그대로).
   - `.github/workflows/docker-images.yml` — main 브랜치 push 시 서버·에이전트 이미지를 GHCR(`ghcr.io/<owner>/vuln-checker-server`, `-agent`)에 자동 빌드·푸시.
   - **실제로 검증**: 컨테이너에서 `main.sh --profile kisa`를 진짜로 실행(스텁 아님) → 72/72 정상 완료 → 서버에 결과 제출까지 end-to-end 확인. `--net host --pid host` 없이 컨테이너 자신의 격리된 뷰만 점검한 것이므로 이건 "메커니즘이 도는지"만 증명한다.
   - **여전히 미검증(Open Question 그대로 남음)**: U-XX/CL-XX 전체 점검을 `--net host --pid host` + 호스트 절대경로 bind mount로 돌렸을 때 bare-metal과 실제로 동일한 결과를 내는지는 검증 못 함 — 개발 머신이 macOS라 `--net host`의 동작 자체가 Linux와 다르고(Docker/Podman이 리눅스 VM 안에서 도는 구조), 이 비교는 실제 Linux 호스트가 있어야 의미가 있다. D-XX 전용 경량 이미지 경로(§4-3에서 "적합"으로 분류된 쪽)는 이번에 만든 이미지로 그대로 커버되지만 아직 실제 Docker 소켓 마운트로 D-XX를 돌려보진 않음 — 다음 세션 후보.
6. **Phase 6 — 운영 강화** (구현 완료 ✅):
   - **토큰 회전**: `Host.agent_token` 단일 필드를 `AgentToken` 테이블로 교체(데이터 마이그레이션으로 기존 토큰 보존). `host.rotate_token(grace_period)` — 기존 토큰에 유예 만료를 걸고 새 토큰 발급, 유예기간 동안 신·구 토큰 공존. 실제로 30초 유예로 회전 → 유예 중엔 둘 다 200, 만료 후 구토큰만 401 확인.
   - **RBAC**: `HostGroup.viewer_group`(auth.Group FK) — 대시보드 전 페이지 `@login_required`(admin 로그인 재사용), `GET /api/hosts`·`/history`는 `IsAuthenticated`. `visible_hosts()`가 superuser는 전체, 일반 사용자는 소속 그룹의 HostGroup만 필터링. 실제로 그룹 소속 여부에 따라 대시보드에 호스트가 보이고 안 보이는 것 확인.
   - **DB 암호화**: `CheckResult.detail`을 Fernet 기반 `EncryptedTextField`로 전환. 실제 DB 원본 값이 `gAAAAA...` 암호문인 것과, 마이그레이션 이전 평문 레코드는 복호화 실패 시 경고 로그 남기고 원문 반환(레거시 호환)하는 것 둘 다 확인.
   - **호스트 그룹별 정책**: `HostGroup.check_interval_hours`/`metrics_interval_seconds` — enroll·heartbeat 응답에 실려 에이전트가 재등록 없이 반영. Go 에이전트는 `time.Ticker.Reset()`으로 상주 중에 주기를 바꾼다. 실제로 그룹 정책(1시간/5초)을 바꾼 뒤 에이전트 로그에서 "정책 변경" 감지 + 메트릭이 실제로 5~6초 간격으로 들어오는 것까지 확인(30초 CLI 기본값에서 전환됨).

---

## 7. 열린 질문

- 에이전트가 `main.sh`를 실행할 때 필요한 root 권한을 어떻게 위임할지(에이전트 상주 프로세스를 root로 돌릴지, sudoers NOPASSWD로 특정 스크립트만 허용할지) — 보안과 운영 편의성 사이 트레이드오프.
- **컨테이너화된 에이전트가 bare-metal 설치 대비 점검 정확도를 얼마나 잃는지 실측 검증 필요** — 특히 SELinux/AppArmor, 커널 모듈, 일부 systemd 상태 점검(§4-2)은 사전에 샘플 서버에서 두 방식 결과를 비교해봐야 함.
- 결과 저장 기간과 DB 용량 — 호스트 수 × 점검 주기 × 200여 개 항목이 누적되므로 오래된 `CheckResult` 상세를 얼마나 보관할지(요약만 남기고 상세는 파기 등) 정책 필요.
- 알림 채널 우선순위 — Slack만 우선 지원할지, 이메일/Webhook까지 처음부터 포함할지.
- 기존 `viewer/index.html`(정적 HTML, 파일 업로드 기반)을 이 플랫폼이 완전히 대체할지, 아니면 "서버 없이 로컬에서 빠르게 보는 용도"로 계속 병행 유지할지.
- Docker 이미지 배포 채널을 Docker Hub로 할지 GHCR로 할지, 버전 태깅/릴리스 정책을 어떻게 잡을지.
