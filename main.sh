#!/bin/bash

################################################################################
# Vulnerability Checker - Main Script
# OS 감지 및 결과 저장을 담당하는 메인 스크립트
################################################################################

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# CLI 옵션 파싱
################################################################################
PARALLEL_MODE="false"
PARALLEL_JOBS=4
PROFILE="default"
ENCRYPT="false"
ENCRYPT_PASS=""

show_help() {
    echo "사용법: sudo $0 [옵션]"
    echo ""
    echo "옵션:"
    echo "  --profile NAME     점검 기준(프로파일) 선택 (기본: default)"
    echo "  --parallel         병렬 실행 모드 (기본: 순차 실행)"
    echo "  --jobs N, -j N     병렬 실행 시 동시 작업 수 (기본: 4)"
    echo "  --encrypt          결과 JSON을 AES-256으로 암호화 저장(.enc), 평문 JSON 제거"
    echo "  --encrypt-pass P   암호화 암호 지정(미지정 시 VC_ENCRYPT_PASS 환경변수 또는 입력 요청)"
    echo "  --list-profiles    사용 가능한 프로파일 목록 표시"
    echo "  --help, -h         도움말 표시"
    echo ""
    echo "프로파일:"
    echo "  default     주요정보통신기반시설(U-01~U-72) + Docker 자동 감지 (기본값)"
    echo "  kisa        주요정보통신기반시설 점검만 (U-01~U-72)"
    echo "  docker      Docker CIS Benchmark 점검만 (D-01~D-68)"
    echo "  all         구현된 모든 기준 실행"
    echo "  cis-linux   CIS Linux Benchmark (CL-01~CL-44)"
    echo "  isms-p      ISMS-P 인증기준 (IS-01~IS-17, 주기반 결과 매핑 기반)"
    echo ""
    echo "예시:"
    echo "  sudo $0                       # 기본 (주기반 + Docker 자동감지)"
    echo "  sudo $0 --profile kisa        # 주기반 점검만"
    echo "  sudo $0 --profile docker      # Docker 점검만"
    echo "  sudo $0 --profile all         # 모든 기준 실행"
    echo "  sudo $0 --parallel -j 8       # 8개씩 병렬 실행"
    exit 0
}

list_profiles() {
    echo "사용 가능한 프로파일:"
    echo "  default     주요정보통신기반시설(U-01~U-72) + Docker 자동 감지 [기본값]"
    echo "  kisa        주요정보통신기반시설 점검만 (U-01~U-72)"
    echo "  docker      Docker CIS Benchmark 점검만 (D-01~D-68)"
    echo "  all         구현된 모든 기준 실행"
    echo "  cis-linux   CIS Linux Benchmark (CL-01~CL-44)"
    echo "  isms-p      ISMS-P 인증기준 (IS-01~IS-17, 주기반 결과 매핑 기반)"
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --profile)
            PROFILE="${2:-default}"
            # 값이 없는 마지막 인자일 때 shift 2가 무한루프를 유발하므로 안전 처리
            shift 2 2>/dev/null || shift
            ;;
        --parallel)
            PARALLEL_MODE="true"
            shift
            ;;
        --encrypt)
            ENCRYPT="true"
            shift
            ;;
        --encrypt-pass)
            ENCRYPT="true"
            ENCRYPT_PASS="${2:-}"
            shift 2 2>/dev/null || shift
            ;;
        --jobs|-j)
            PARALLEL_JOBS="${2:-4}"
            shift 2 2>/dev/null || shift
            ;;
        --list-profiles)
            list_profiles
            ;;
        --help|-h)
            show_help
            ;;
        *)
            echo -e "${RED}[오류] 알 수 없는 옵션: $1${NC}"
            show_help
            ;;
    esac
done

# 프로파일 유효성 검사
case "$PROFILE" in
    default|kisa|docker|all|isms-p|cis-linux)
        ;;
    *)
        echo -e "${RED}[오류] 알 수 없는 프로파일: ${PROFILE}${NC}"
        echo -e "${YELLOW}  --list-profiles 로 사용 가능한 프로파일을 확인하세요.${NC}"
        exit 1
        ;;
esac

export PARALLEL_MODE PARALLEL_JOBS PROFILE

################################################################################
# 결과 암호화 (--encrypt): AES-256-CBC + PBKDF2-HMAC-SHA256, openssl 봉투 포맷
#   출력: base64 텍스트 (Salted__ + salt + ciphertext). 뷰어가 Web Crypto로 복호화.
################################################################################
VC_ENCRYPT_ITER=200000

resolve_encrypt_pass() {
    # 우선순위: --encrypt-pass > VC_ENCRYPT_PASS 환경변수 > 대화형 입력
    if [ -n "$ENCRYPT_PASS" ]; then
        return 0
    fi
    if [ -n "${VC_ENCRYPT_PASS:-}" ]; then
        ENCRYPT_PASS="$VC_ENCRYPT_PASS"
        return 0
    fi
    if [ -t 0 ]; then
        local p1 p2
        read -r -s -p "암호화 암호 입력: " p1; echo "" >&2
        read -r -s -p "암호 확인:       " p2; echo "" >&2
        if [ "$p1" != "$p2" ]; then
            echo -e "${RED}[오류] 암호가 일치하지 않습니다.${NC}" >&2
            return 1
        fi
        if [ -z "$p1" ]; then
            echo -e "${RED}[오류] 빈 암호는 사용할 수 없습니다.${NC}" >&2
            return 1
        fi
        ENCRYPT_PASS="$p1"
        return 0
    fi
    echo -e "${RED}[오류] 암호화 암호가 없습니다. --encrypt-pass 또는 VC_ENCRYPT_PASS를 지정하세요.${NC}" >&2
    return 1
}

encrypt_file() {
    # $1=평문 파일. 성공 시 "$1.enc" 생성 후 평문 삭제, 경로 출력.
    local src="$1"
    [ -f "$src" ] || return 1
    local enc="${src}.enc"
    if openssl enc -aes-256-cbc -salt -pbkdf2 -iter "$VC_ENCRYPT_ITER" -md sha256 -base64 -A \
        -in "$src" -out "$enc" -pass "pass:${ENCRYPT_PASS}" 2>/dev/null; then
        rm -f "$src"
        printf '%s\n' "$enc"
        return 0
    fi
    rm -f "$enc" 2>/dev/null
    return 1
}

################################################################################
# root 권한 확인
################################################################################
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[오류] 이 스크립트는 root 권한으로 실행해야 합니다.${NC}"
    echo -e "${YELLOW}  실행 방법: sudo ${0}${NC}"
    exit 1
fi

# 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="${SCRIPT_DIR}/scripts"
RESULTS_DIR="${SCRIPT_DIR}/results"
LOGS_DIR="${SCRIPT_DIR}/logs"

# 타임스탬프
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${LOGS_DIR}/run_${TIMESTAMP}.log"
RESULT_FILE="${RESULTS_DIR}/result_${TIMESTAMP}.txt"
SUMMARY_FILE="${RESULTS_DIR}/summary_${TIMESTAMP}.md"
JSON_FILE="${RESULTS_DIR}/result_${TIMESTAMP}.json"

################################################################################
# 함수: OS 감지
################################################################################
detect_os() {
    local os_type

    case "$(uname -s)" in
        Linux*)
            os_type="LINUX"
            ;;
        Darwin*)
            os_type="MACOS"
            ;;
        *)
            os_type="UNKNOWN"
            ;;
    esac

    echo "$os_type"
}

################################################################################
# 함수: Linux 배포판 감지
################################################################################
detect_linux_distro() {
    local distro="UNKNOWN"
    
    if [ -f /etc/os-release ]; then
        distro=$(grep "^ID=" /etc/os-release | cut -d'=' -f2 | tr -d '"')
    elif [ -f /etc/redhat-release ]; then
        distro="rhel"
    elif [ -f /etc/debian_version ]; then
        distro="debian"
    fi
    
    echo "$distro"
}

################################################################################
# 함수: macOS 버전 감지
################################################################################
detect_macos_version() {
    sw_vers -productVersion
}

################################################################################
# 함수: 로그 출력
################################################################################
log() {
    local level="$1"
    shift
    local message="$@"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    echo "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
}

################################################################################
# 함수: 초기화
################################################################################
init() {
    # 결과 파일 초기화 (주기반 점검이 포함된 프로파일에서만 생성)
    if profile_includes_kisa; then
        {
            echo "===================================================="
            echo "Vulnerability Checker 결과"
            echo "===================================================="
            echo "실행일시: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "OS: ${OS_TYPE}"
            echo "===================================================="
        } > "$RESULT_FILE"
    fi

    log "INFO" "=================================="
    log "INFO" "Vulnerability Checker 시작"
    log "INFO" "=================================="
    log "INFO" "OS: ${OS_TYPE}"
    log "INFO" "스크립트 디렉토리: ${SCRIPT_DIR}"
    log "INFO" "결과 저장 디렉토리: ${RESULTS_DIR}"
    if [ "$PARALLEL_MODE" = "true" ]; then
        log "INFO" "실행 모드: 병렬 (동시 ${PARALLEL_JOBS}개)"
    else
        log "INFO" "실행 모드: 순차"
    fi
}

################################################################################
# 함수: 마크다운 요약 생성
################################################################################
generate_summary() {
    local pass_count="$1"
    local fail_count="$2"
    local review_count="$3"
    local total_count="$4"
    local run_date
    run_date=$(date '+%Y-%m-%d %H:%M:%S')
    local hostname
    hostname=$(hostname 2>/dev/null || echo "unknown")

    # 취약/확인필요 항목 목록 추출
    local fail_list review_list
    fail_list=$(awk '/^\[U-[0-9]/{code=$0} /점검 결과: 취약/{print code}' "$RESULT_FILE")
    review_list=$(awk '/^\[U-[0-9]/{code=$0} /점검 결과: 확인필요/{print code}' "$RESULT_FILE")

    {
        echo "# 취약점 점검 결과 요약"
        echo ""
        echo "| 항목 | 내용 |"
        echo "|------|------|"
        echo "| 점검 일시 | ${run_date} |"
        echo "| 호스트명 | ${hostname} |"
        echo "| OS | ${OS_TYPE} |"
        echo "| 결과 파일 | $(basename "$RESULT_FILE") |"
        echo ""
        echo "## 점검 결과 통계"
        echo ""
        echo "| 구분 | 건수 | 비율 |"
        echo "|------|-----:|-----:|"
        echo "| ✅ 양호 | ${pass_count} | $(( total_count > 0 ? pass_count * 100 / total_count : 0 ))% |"
        echo "| ❌ 취약 | ${fail_count} | $(( total_count > 0 ? fail_count * 100 / total_count : 0 ))% |"
        echo "| ⚠️ 확인필요 | ${review_count} | $(( total_count > 0 ? review_count * 100 / total_count : 0 ))% |"
        echo "| **합계** | **${total_count}** | **100%** |"
        echo ""

        if [ -n "$fail_list" ]; then
            echo "## ❌ 취약 항목 목록"
            echo ""
            while IFS= read -r line; do
                local code detail
                code=$(echo "$line" | grep -oE "U-[0-9]+")
                detail=$(echo "$line" | sed 's/\[U-[0-9]*\] //')
                echo "- **${code}** ${detail}"
            done <<< "$fail_list"
            echo ""
        fi

        if [ -n "$review_list" ]; then
            echo "## ⚠️ 확인필요 항목 목록"
            echo ""
            while IFS= read -r line; do
                local code detail
                code=$(echo "$line" | grep -oE "U-[0-9]+")
                detail=$(echo "$line" | sed 's/\[U-[0-9]*\] //')
                echo "- **${code}** ${detail}"
            done <<< "$review_list"
            echo ""
        fi

        echo "## 상세 결과"
        echo ""
        echo "> 상세 점검 내용은 \`$(basename "$RESULT_FILE")\` 파일을 참고하세요."
    } > "$SUMMARY_FILE"
}

################################################################################
# 함수: 종료 처리
################################################################################
finalize() {
    local status=$1
    local message=$2
    
    if [ $status -eq 0 ]; then
        log "INFO" "✓ ${message}"
        echo -e "${GREEN}✓ ${message}${NC}"
    else
        log "ERROR" "✗ ${message}"
        echo -e "${RED}✗ ${message}${NC}"
    fi
    
    log "INFO" "=================================="
    log "INFO" "Vulnerability Checker 종료"
    log "INFO" "=================================="
}

################################################################################
# 함수: 통합 JSON 생성
# 여러 기준(주기반/Docker/CIS Linux)의 JSON에서 checks 배열을 추출·병합하고
# 각 항목에 "standard" 필드를 주입해 단일 통합 JSON으로 생성한다.
# 사용법: build_combined_json <out> <run_date> <hostname> <arch> "라벨|경로" ...
################################################################################
build_combined_json() {
    local out="$1"; shift
    local run_date="$1"; shift
    local hostname="$1"; shift
    local arch="$1"; shift

    local tmp
    tmp=$(mktemp /tmp/vuln_combined_XXXXXX 2>/dev/null || echo "/tmp/vuln_combined_$$")
    > "$tmp"

    local pair label path label_list=""
    for pair in "$@"; do
        label="${pair%%|*}"
        path="${pair#*|}"
        [ -f "$path" ] || continue
        label_list="${label_list:+${label_list} + }${label}"
        # checks 배열의 각 항목 라인 추출 → 끝 콤마 제거 → standard 필드 주입
        awk 'BEGIN{f=0} /"checks": \[/{f=1; next} f && /^[[:space:]]*\]/{f=0} f{print}' "$path" \
            | sed 's/,[[:space:]]*$//' \
            | sed "s/^{/{\"standard\":\"${label}\",/" >> "$tmp"
    done

    if [ ! -s "$tmp" ]; then rm -f "$tmp"; return 1; fi

    local pass fail review total
    pass=$(grep -c '"status":"PASS"'     "$tmp"); pass=${pass:-0}
    fail=$(grep -c '"status":"FAIL"'     "$tmp"); fail=${fail:-0}
    review=$(grep -c '"status":"REVIEW"' "$tmp"); review=${review:-0}
    total=$(( pass + fail + review ))

    # 마지막 항목을 제외한 모든 라인에 콤마 추가
    local checks_json
    checks_json=$(sed '$!s/$/,/' "$tmp")

    local esc_hostname
    esc_hostname=$(json_escape "$hostname")

    cat > "$out" <<JSONEOF
{
  "metadata": {
    "executionTime": "${run_date}",
    "hostname": "${esc_hostname}",
    "os": "통합",
    "distro": "${label_list}",
    "architecture": "${arch}"
  },
  "summary": {
    "total": ${total},
    "pass": ${pass},
    "fail": ${fail},
    "review": ${review}
  },
  "checks": [
${checks_json}
  ]
}
JSONEOF

    rm -f "$tmp"
    return 0
}

################################################################################
# 함수: 프로파일 판정
################################################################################
# 현재 프로파일에 KISA(주기반 U-01~U-72) 점검이 포함되는지
# isms-p는 주기반 결과를 소스로 판정을 파생하므로 주기반 점검을 함께 실행한다
profile_includes_kisa() {
    case "$PROFILE" in
        default|kisa|all|isms-p) return 0 ;;
        *) return 1 ;;
    esac
}

# 현재 프로파일에 ISMS-P(매핑 기반) 점검이 포함되는지
profile_includes_isms_p() {
    case "$PROFILE" in
        isms-p|all) return 0 ;;
        *) return 1 ;;
    esac
}

# 현재 프로파일에 Docker 점검이 포함되는지
profile_includes_docker() {
    case "$PROFILE" in
        default|docker|all) return 0 ;;
        *) return 1 ;;
    esac
}

# 현재 프로파일에 CIS Linux Benchmark 점검이 포함되는지
profile_includes_cis_linux() {
    case "$PROFILE" in
        cis-linux|all) return 0 ;;
        *) return 1 ;;
    esac
}

################################################################################
# 메인 로직
################################################################################
main() {
    # 필요한 디렉토리 생성
    mkdir -p "${LOGS_DIR}" "${RESULTS_DIR}"
    
    # 공통 함수 먼저 로드
    if [ -f "${SCRIPTS_DIR}/common.sh" ]; then
        source "${SCRIPTS_DIR}/common.sh"
    fi
    
    # OS 감지
    OS_TYPE=$(detect_os)
    
    # JSON 초기화
    init_json

    # 초기화
    init

    # 필수 명령어 사전 확인
    check_prerequisites

    local result=0
    log "INFO" "실행 프로파일: ${PROFILE}"

    if [ "$PROFILE" = "isms-p" ]; then
        echo -e "${BLUE}[ISMS-P] ISMS-P 판정의 소스로 주기반(U-01~U-72) 점검을 먼저 실행합니다.${NC}"
    fi

    # OS별 스크립트 실행 (KISA 주기반 점검 — U-01~U-72)
    if profile_includes_kisa; then
        case "$OS_TYPE" in
            LINUX)
                local DISTRO=$(detect_linux_distro)
                log "INFO" "Linux 배포판: ${DISTRO}"
                log "INFO" "Linux 스크립트 실행 중..."

                if [ -f "${SCRIPTS_DIR}/linux.sh" ]; then
                    source "${SCRIPTS_DIR}/linux.sh"
                    run_linux_checks "$DISTRO"
                    result=$?
                else
                    log "ERROR" "linux.sh를 찾을 수 없습니다"
                    result=1
                fi
                ;;
            MACOS)
                local MACOS_VERSION=$(detect_macos_version)
                log "INFO" "macOS 버전: ${MACOS_VERSION}"
                log "INFO" "macOS 스크립트 실행 중..."

                if [ -f "${SCRIPTS_DIR}/macos.sh" ]; then
                    source "${SCRIPTS_DIR}/macos.sh"
                    run_macos_checks "$MACOS_VERSION"
                    result=$?
                else
                    log "ERROR" "macos.sh를 찾을 수 없습니다"
                    result=1
                fi
                ;;
            *)
                log "ERROR" "지원하지 않는 OS입니다: ${OS_TYPE}"
                result=1
                ;;
        esac
    else
        log "INFO" "프로파일 '${PROFILE}': 주기반(U-01~U-72) 점검 건너뜀"
    fi

    # Docker 점검 실행
    if profile_includes_docker; then
        if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
            log "INFO" "Docker 감지됨 — Docker 보안 점검 실행 중..."
            echo -e "${BLUE}[Docker] Docker 환경이 감지되었습니다. CIS Docker Benchmark 점검을 시작합니다...${NC}"
            if [ -f "${SCRIPT_DIR}/docker/main.sh" ]; then
                export RESULTS_DIR
                source "${SCRIPT_DIR}/docker/main.sh"
                run_docker_checks
            else
                log "ERROR" "docker/main.sh를 찾을 수 없습니다"
            fi
        elif [ "$PROFILE" = "docker" ]; then
            # docker 프로파일을 명시했는데 Docker 환경이 없는 경우 안내
            log "WARNING" "Docker를 찾을 수 없거나 데몬이 실행 중이 아닙니다"
            echo -e "${YELLOW}[Docker] Docker가 설치되어 있지 않거나 데몬이 실행 중이 아닙니다.${NC}"
            result=1
        fi
    else
        log "INFO" "프로파일 '${PROFILE}': Docker 점검 건너뜀"
    fi

    # CIS Linux Benchmark 점검 실행
    if profile_includes_cis_linux; then
        if [ "$OS_TYPE" != "LINUX" ]; then
            log "WARNING" "CIS Linux Benchmark는 Linux 환경에서만 의미가 있습니다 (현재: ${OS_TYPE})"
            echo -e "${YELLOW}[CIS-Linux] Linux 환경이 아니므로 일부 항목이 '확인필요'로 처리됩니다.${NC}"
        fi
        log "INFO" "CIS Linux Benchmark 점검 실행 중..."
        echo -e "${BLUE}[CIS-Linux] CIS Linux Benchmark 점검을 시작합니다...${NC}"
        if [ -f "${SCRIPT_DIR}/cis-linux/main.sh" ]; then
            export RESULTS_DIR
            source "${SCRIPT_DIR}/cis-linux/main.sh"
            run_cis_linux_checks
        else
            log "ERROR" "cis-linux/main.sh를 찾을 수 없습니다"
        fi
    fi

    # 결과 집계
    # grep -c는 일치가 없어도 "0"을 출력하므로 `|| echo 0`을 붙이면 "0\n0"이 되어
    # 산술식이 깨진다. 출력을 그대로 받고 비어있을 때만 0으로 보정한다.
    local pass_count=0 fail_count=0 review_count=0
    if [ -f "$RESULT_FILE" ]; then
        pass_count=$(grep -c "점검 결과: 양호"    "$RESULT_FILE" 2>/dev/null); pass_count=${pass_count:-0}
        fail_count=$(grep -c "점검 결과: 취약"    "$RESULT_FILE" 2>/dev/null); fail_count=${fail_count:-0}
        review_count=$(grep -c "점검 결과: 확인필요" "$RESULT_FILE" 2>/dev/null); review_count=${review_count:-0}
    fi
    local total_count=$(( pass_count + fail_count + review_count ))

    local run_date
    run_date=$(date '+%Y-%m-%dT%H:%M:%S')
    local json_hostname
    json_hostname=$(hostname 2>/dev/null || echo "unknown")
    local json_distro="${DISTRO:-}"
    local json_arch
    json_arch=$(uname -m 2>/dev/null || echo "unknown")

    # 주기반 결과 파일 마무리·요약·JSON 생성 (주기반 점검이 실행된 경우에만)
    if profile_includes_kisa && [ -f "$RESULT_FILE" ]; then
        {
            echo ""
            echo "===================================================="
            echo "검사 완료: 총 ${total_count}개  양호 ${pass_count}  취약 ${fail_count}  확인필요 ${review_count}"
            echo "===================================================="
        } >> "$RESULT_FILE"

        # 마크다운 요약 파일 생성
        generate_summary "$pass_count" "$fail_count" "$review_count" "$total_count"

        # JSON 결과 파일 생성
        generate_json "$JSON_FILE" "$run_date" "$json_hostname" "$OS_TYPE" "$json_distro" "$json_arch" \
            "$pass_count" "$fail_count" "$review_count" "$total_count"

        log "INFO" "JSON 저장: ${JSON_FILE}"
        log "INFO" "요약 저장: ${SUMMARY_FILE}"
    fi

    # ISMS-P 점검 (주기반 결과 JSON을 소스로 매핑 기반 판정 파생)
    if profile_includes_isms_p; then
        if [ "$total_count" -gt 0 ] && [ -f "$JSON_FILE" ]; then
            log "INFO" "ISMS-P 매핑 점검 실행 중..."
            echo -e "${BLUE}[ISMS-P] 주기반 결과를 기반으로 ISMS-P 인증기준 판정을 생성합니다...${NC}"
            if [ -f "${SCRIPT_DIR}/isms-p/main.sh" ]; then
                export RESULTS_DIR
                source "${SCRIPT_DIR}/isms-p/main.sh"
                run_isms_p_checks "$JSON_FILE"
            else
                log "ERROR" "isms-p/main.sh를 찾을 수 없습니다"
            fi
        else
            log "WARNING" "주기반 점검 결과가 없어 ISMS-P 판정을 생성할 수 없습니다"
            echo -e "${YELLOW}[ISMS-P] 주기반(U-XX) 결과가 없어 ISMS-P 점검을 건너뜁니다.${NC}"
        fi
    fi

    # 통합 JSON 생성 (2개 이상 기준이 점검된 경우 result_all_*.json 추가 생성)
    local combined_pairs=()
    [ "$total_count" -gt 0 ] && combined_pairs+=("주기반|${JSON_FILE}")
    [ -n "${DOCKER_JSON_OUTPUT:-}" ] && [ -f "${DOCKER_JSON_OUTPUT:-/nonexistent}" ] && combined_pairs+=("Docker|${DOCKER_JSON_OUTPUT}")
    [ -n "${CIS_JSON_OUTPUT:-}" ] && [ -f "${CIS_JSON_OUTPUT:-/nonexistent}" ] && combined_pairs+=("CIS Linux|${CIS_JSON_OUTPUT}")
    [ -n "${ISMSP_JSON_OUTPUT:-}" ] && [ -f "${ISMSP_JSON_OUTPUT:-/nonexistent}" ] && combined_pairs+=("ISMS-P|${ISMSP_JSON_OUTPUT}")
    if [ "${#combined_pairs[@]}" -ge 2 ]; then
        local combined_file="${RESULTS_DIR}/result_all_${TIMESTAMP}.json"
        if build_combined_json "$combined_file" "$run_date" "$json_hostname" "$json_arch" "${combined_pairs[@]}"; then
            log "INFO" "통합 JSON 저장: ${combined_file}"
            echo -e "${GREEN}[통합] 모든 기준 통합 결과: ${combined_file}${NC}"
        fi
    fi

    # 결과 JSON 암호화 (--encrypt)
    if [ "$ENCRYPT" = "true" ]; then
        if ! command -v openssl >/dev/null 2>&1; then
            log "WARN" "openssl이 없어 암호화를 건너뜁니다."
            echo -e "${YELLOW}[암호화] openssl 미설치 — 평문 JSON으로 유지됩니다.${NC}"
        elif resolve_encrypt_pass; then
            local enc_targets=() enc_out enc_count=0
            [ "$total_count" -gt 0 ] && enc_targets+=("$JSON_FILE")
            [ -n "${DOCKER_JSON_OUTPUT:-}" ] && [ -f "${DOCKER_JSON_OUTPUT:-/nonexistent}" ] && enc_targets+=("$DOCKER_JSON_OUTPUT")
            [ -n "${CIS_JSON_OUTPUT:-}" ] && [ -f "${CIS_JSON_OUTPUT:-/nonexistent}" ] && enc_targets+=("$CIS_JSON_OUTPUT")
            [ -n "${ISMSP_JSON_OUTPUT:-}" ] && [ -f "${ISMSP_JSON_OUTPUT:-/nonexistent}" ] && enc_targets+=("$ISMSP_JSON_OUTPUT")
            [ -n "${combined_file:-}" ] && [ -f "${combined_file:-/nonexistent}" ] && enc_targets+=("$combined_file")
            local f
            for f in "${enc_targets[@]}"; do
                if enc_out=$(encrypt_file "$f"); then
                    log "INFO" "암호화 저장: ${enc_out}"
                    enc_count=$((enc_count + 1))
                else
                    log "WARN" "암호화 실패: ${f}"
                fi
            done
            unset ENCRYPT_PASS
            echo -e "${GREEN}[암호화] ${enc_count}개 JSON을 AES-256으로 암호화했습니다 (.enc).${NC}"
            echo -e "${YELLOW}  ⚠ .txt/.md 보고서는 평문으로 남습니다 — 외부 전달 시 직접 처리하세요.${NC}"
            echo -e "${YELLOW}  뷰어(viewer/index.html)에서 .enc 파일을 열고 암호를 입력하면 복호화됩니다.${NC}"
        else
            log "WARN" "암호 확인 실패로 암호화를 건너뜁니다."
        fi
    fi

    # 종료 처리 (실행된 모든 기준의 결과를 합산해 표시)
    local overall_pass=$(( pass_count + ${DOCKER_PASS_COUNT:-0} + ${CIS_PASS_COUNT:-0} + ${ISMSP_PASS_COUNT:-0} ))
    local overall_fail=$(( fail_count + ${DOCKER_FAIL_COUNT:-0} + ${CIS_FAIL_COUNT:-0} + ${ISMSP_FAIL_COUNT:-0} ))
    local overall_review=$(( review_count + ${DOCKER_REVIEW_COUNT:-0} + ${CIS_REVIEW_COUNT:-0} + ${ISMSP_REVIEW_COUNT:-0} ))
    local overall_total=$(( overall_pass + overall_fail + overall_review ))

    if [ $result -eq 0 ]; then
        finalize 0 "모든 검사 완료 (총 ${overall_total}개 | 양호 ${overall_pass} / 취약 ${overall_fail} / 확인필요 ${overall_review}) | 결과: ${RESULTS_DIR}/"
    else
        finalize 1 "검사 중 오류 발생"
    fi
    
    return $result
}

# 스크립트 실행
main
exit $?
