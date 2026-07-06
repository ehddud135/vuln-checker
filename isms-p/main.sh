#!/bin/bash

################################################################################
# ISMS-P 인증기준 점검 진입점 (매핑 기반)
# 주기반(U-01~U-72) 점검 결과 JSON을 소스로 ISMS-P 항목 판정을 파생한다.
# 사용법: run_isms_p_checks <kisa_result_json>
################################################################################

ISMSP_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "${ISMSP_SCRIPT_DIR}/scripts/common.sh"

# 점검 결과 카운터
ISMSP_PASS_COUNT=0
ISMSP_FAIL_COUNT=0
ISMSP_REVIEW_COUNT=0

run_isms_p_checks() {
    local kisa_json="$1"

    if ! load_kisa_results "$kisa_json"; then
        echo "  [ISMS-P] 주기반 점검 결과 JSON을 읽을 수 없습니다: ${kisa_json}" >&2
        echo "  [ISMS-P] ISMS-P 점검은 주기반(U-XX) 결과를 소스로 사용합니다." >&2
        return 1
    fi

    local exec_time
    exec_time=$(date '+%Y-%m-%d %H:%M:%S')
    local hostname
    hostname=$(hostname 2>/dev/null || echo "unknown")
    local distro="unknown"
    if [ -f /etc/os-release ]; then
        distro=$(grep "^PRETTY_NAME=" /etc/os-release 2>/dev/null | cut -d'=' -f2 | tr -d '"')
    fi
    local arch
    arch=$(uname -m 2>/dev/null || echo "unknown")

    local ts
    ts=$(date '+%Y%m%d_%H%M%S')
    local result_dir="${RESULTS_DIR:-./results}"
    mkdir -p "$result_dir"

    ISMSP_RESULT_FILE="${result_dir}/isms_p_result_${ts}.txt"
    local json_file="${result_dir}/isms_p_result_${ts}.json"
    # 통합 JSON 생성을 위해 경로를 전역으로 노출 (main.sh에서 참조)
    ISMSP_JSON_OUTPUT="$json_file"

    init_ismsp_json

    # 헤더 출력
    {
        echo "========================================================"
        echo "  ISMS-P 인증기준(보호대책) 점검 보고서 — 매핑 기반"
        echo "========================================================"
        echo ""
        echo "  점검 일시  : ${exec_time}"
        echo "  호스트명   : ${hostname}"
        echo "  배포판     : ${distro}"
        echo "  아키텍처   : ${arch}"
        echo "  소스 결과  : $(basename "$kisa_json")"
        echo ""
        echo "  ※ 판정 방식: 주기반(U-XX) 점검 결과를 인증기준별로 집계"
        echo "     - 매핑 항목 중 하나라도 취약 → 취약"
        echo "     - 확인필요 존재 → 확인필요 / 모두 양호 → 양호"
        echo "     - 매핑이 없는 항목(정책·절차)은 수동 점검 안내와 함께 확인필요"
        echo ""
        echo "========================================================"
    } > "$ISMSP_RESULT_FILE"

    # 항목별 판정 파생
    local code status_kr
    local current_category=""
    for code in "${ISMSP_ORDER[@]}"; do
        local category
        category=$(get_ismsp_category "$code")
        if [ "$category" != "$current_category" ]; then
            current_category="$category"
            {
                echo ""
                echo "--------------------------------------------------------"
                echo "  ${current_category}"
                echo "--------------------------------------------------------"
            } >> "$ISMSP_RESULT_FILE"
        fi

        derive_ismsp_item "$code"

        case "$DERIVED_STATUS" in
            PASS)   status_kr="✅ 양호";     ISMSP_PASS_COUNT=$((ISMSP_PASS_COUNT + 1)) ;;
            FAIL)   status_kr="❌ 취약";     ISMSP_FAIL_COUNT=$((ISMSP_FAIL_COUNT + 1)) ;;
            *)      status_kr="⚠️  확인필요"; ISMSP_REVIEW_COUNT=$((ISMSP_REVIEW_COUNT + 1)) ;;
        esac

        {
            echo ""
            echo "[${code}] ${ISMSP_CODES[$code]}"
            echo ""
            echo "  [ 점검 목적 ]"
            echo "  ${ISMSP_DETAILS[${code}_PURPOSE]}"
            echo ""
            echo "  [ 점검 방법 ]"
            echo "  ${ISMSP_DETAILS[${code}_CHECK]}"
            echo ""
            echo "  ${status_kr}"
            echo "  상세: ${DERIVED_DETAIL}"
        } >> "$ISMSP_RESULT_FILE"

        record_ismsp_json_check "$code" "$DERIVED_STATUS" "$DERIVED_DETAIL"
    done

    # 요약
    local total_count=$((ISMSP_PASS_COUNT + ISMSP_FAIL_COUNT + ISMSP_REVIEW_COUNT))
    {
        echo ""
        echo "========================================================"
        echo "  점검 결과 요약"
        echo "========================================================"
        echo ""
        printf "  %-14s %d건\n" "✅ 양호(PASS):"   "$ISMSP_PASS_COUNT"
        printf "  %-14s %d건\n" "❌ 취약(FAIL):"   "$ISMSP_FAIL_COUNT"
        printf "  %-14s %d건\n" "⚠️  확인필요:"    "$ISMSP_REVIEW_COUNT"
        printf "  %-14s %d건\n" "합계:"             "$total_count"
        echo ""
        echo "  JSON 결과: ${json_file}"
        echo "========================================================"
    } >> "$ISMSP_RESULT_FILE"

    # JSON 생성
    generate_ismsp_json "$json_file" "$exec_time" "$hostname" "$distro" "$arch" \
        "$ISMSP_PASS_COUNT" "$ISMSP_FAIL_COUNT" "$ISMSP_REVIEW_COUNT" "$total_count"

    # 콘솔 출력
    echo ""
    echo "  [ISMS-P 점검 완료]"
    echo "  ✅ 양호: ${ISMSP_PASS_COUNT}  ❌ 취약: ${ISMSP_FAIL_COUNT}  ⚠️  확인필요: ${ISMSP_REVIEW_COUNT}  (합계: ${total_count})"
    echo "  결과 파일: ${ISMSP_RESULT_FILE}"
    echo "  JSON 파일: ${json_file}"
}
