#!/bin/bash

################################################################################
# ISMS-P 공통 함수 라이브러리
# KISA 주기반(U-XX) 결과 JSON을 소스로 매핑 기반 판정을 파생한다.
################################################################################

source "$(dirname "${BASH_SOURCE[0]}")/security_codes.sh"
source "$(dirname "${BASH_SOURCE[0]}")/security_details.sh"
source "$(dirname "${BASH_SOURCE[0]}")/mapping.sh"

################################################################################
# JSON 관련 변수 및 함수
################################################################################

ISMSP_JSON_CHECKS_TMP=""

init_ismsp_json() {
    ISMSP_JSON_CHECKS_TMP=$(mktemp /tmp/ismsp_json_XXXXXX 2>/dev/null || echo "/tmp/ismsp_json_$$")
    > "$ISMSP_JSON_CHECKS_TMP"
}

# json_escape는 main.sh의 common.sh에서 이미 정의되어 있으나
# 독립 실행을 대비해 미정의 시에만 정의
if ! declare -f json_escape >/dev/null 2>&1; then
    json_escape() {
        local str="$1"
        str="${str//\\/\\\\}"
        str="${str//\"/\\\"}"
        str="${str//$'\n'/\\n}"
        str="${str//$'\r'/}"
        str="${str//$'\t'/\\t}"
        echo -n "$str"
    }
fi

record_ismsp_json_check() {
    local code="$1"
    local status="$2"
    local detail="$3"
    local name=$(json_escape "${ISMSP_CODES[$code]}")
    local category=$(json_escape "$(get_ismsp_category "$code")")
    local esc_detail=$(json_escape "$detail")
    local purpose=$(json_escape "${ISMSP_DETAILS[${code}_PURPOSE]}")
    local check=$(json_escape "${ISMSP_DETAILS[${code}_CHECK]}")
    local good=$(json_escape "${ISMSP_DETAILS[${code}_GOOD]}")
    local bad=$(json_escape "${ISMSP_DETAILS[${code}_BAD]}")
    local action=$(json_escape "${ISMSP_DETAILS[${code}_ACTION]}")
    local threat=$(json_escape "${ISMSP_DETAILS[${code}_THREAT]}")

    cat >> "$ISMSP_JSON_CHECKS_TMP" <<JSONENTRY
{"code":"${code}","name":"${name}","category":"${category}","status":"${status}","detail":"${esc_detail}","reference":{"purpose":"${purpose}","check":"${check}","goodCriteria":"${good}","badCriteria":"${bad}","remediation":"${action}","threat":"${threat}"}},
JSONENTRY
}

generate_ismsp_json() {
    local json_file="$1"
    local exec_time="$2"
    local hostname="$3"
    local distro="$4"
    local arch="$5"
    local pass_count="$6"
    local fail_count="$7"
    local review_count="$8"
    local total_count="$9"

    local esc_hostname=$(json_escape "$hostname")
    local esc_distro=$(json_escape "$distro")

    local checks_json=""
    if [ -f "$ISMSP_JSON_CHECKS_TMP" ] && [ -s "$ISMSP_JSON_CHECKS_TMP" ]; then
        checks_json=$(sed '$ s/,$//' "$ISMSP_JSON_CHECKS_TMP")
    fi

    cat > "$json_file" <<JSONEOF
{
  "metadata": {
    "executionTime": "${exec_time}",
    "hostname": "${esc_hostname}",
    "os": "ISMS-P",
    "distro": "${esc_distro}",
    "architecture": "${arch}"
  },
  "summary": {
    "total": ${total_count},
    "pass": ${pass_count},
    "fail": ${fail_count},
    "review": ${review_count}
  },
  "checks": [
${checks_json}
  ]
}
JSONEOF

    rm -f "$ISMSP_JSON_CHECKS_TMP"
}

################################################################################
# KISA 결과 JSON 파싱
# checks 배열의 각 항목이 한 줄 JSON 객체라는 생성 규칙(record_json_check)에 의존
################################################################################

declare -A KISA_STATUS=()
declare -A KISA_DETAIL=()

load_kisa_results() {
    local src="$1"
    [ -f "$src" ] || return 1

    KISA_STATUS=()
    KISA_DETAIL=()

    local line code status detail
    while IFS= read -r line; do
        case "$line" in
            '{"code":"U-'*) ;;
            *) continue ;;
        esac
        code=$(printf '%s' "$line" | sed -n 's/^{"code":"\(U-[0-9]*\)".*/\1/p')
        [ -n "$code" ] || continue
        status=$(printf '%s' "$line" | grep -o '"status":"[A-Z]*"' | head -1 | cut -d'"' -f4)
        detail=$(printf '%s' "$line" | sed -n 's/.*"detail":"\(.*\)","reference".*/\1/p')
        KISA_STATUS["$code"]="$status"
        KISA_DETAIL["$code"]="$detail"
    done < "$src"

    [ "${#KISA_STATUS[@]}" -gt 0 ]
}

################################################################################
# 판정 파생: 매핑된 U-XX 결과를 집계
#   하나라도 FAIL → FAIL / 아니면 REVIEW 있으면 REVIEW / 모두 PASS → PASS
# 결과는 전역 DERIVED_STATUS / DERIVED_DETAIL 에 저장
################################################################################

derive_ismsp_item() {
    local code="$1"
    local mapping="${ISMSP_MAP[$code]}"

    if [ -z "$mapping" ]; then
        DERIVED_STATUS="REVIEW"
        DERIVED_DETAIL="[수동 점검] ${ISMSP_MANUAL_NOTE[$code]:-자동 판정이 불가능한 항목입니다. 담당자 확인이 필요합니다.}"
        return
    fi

    local u fail_list="" review_list="" pass_count=0 missing_list="" total=0
    for u in $mapping; do
        total=$((total + 1))
        case "${KISA_STATUS[$u]:-}" in
            FAIL)   fail_list="${fail_list:+${fail_list}, }${u}" ;;
            REVIEW) review_list="${review_list:+${review_list}, }${u}" ;;
            PASS)   pass_count=$((pass_count + 1)) ;;
            *)      missing_list="${missing_list:+${missing_list}, }${u}" ;;
        esac
    done

    local summary="매핑 ${total}건 중 양호 ${pass_count}건"
    [ -n "$fail_list" ]    && summary="${summary} / 취약: ${fail_list}"
    [ -n "$review_list" ]  && summary="${summary} / 확인필요: ${review_list}"
    [ -n "$missing_list" ] && summary="${summary} / 결과없음: ${missing_list}"

    if [ -n "$fail_list" ]; then
        DERIVED_STATUS="FAIL"
        DERIVED_DETAIL="${summary} — 취약으로 판정된 주기반 항목을 먼저 조치하세요."
    elif [ -n "$review_list" ] || [ -n "$missing_list" ]; then
        DERIVED_STATUS="REVIEW"
        DERIVED_DETAIL="${summary} — 확인필요 항목의 담당자 확인이 필요합니다."
    else
        DERIVED_STATUS="PASS"
        DERIVED_DETAIL="${summary} — 매핑된 주기반 항목이 모두 양호합니다."
    fi
}
