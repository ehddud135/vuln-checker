#!/bin/bash
# 섹션 5: 접근 및 인증 (CL-32 ~ CL-38)

# sshd_config에서 지시어 값 추출 (마지막 유효 설정)
_cis_sshd_get() {
    local key="$1"
    [ -f /etc/ssh/sshd_config ] || return 1
    grep -iE "^\s*${key}\s+" /etc/ssh/sshd_config 2>/dev/null | grep -v "^#" | awk '{print $2}' | tail -1
}

check_CL_32() {
    cis_print_check "CL-32"
    local cron_active="false"
    if cis_service_active cron || cis_service_active crond; then
        cron_active="true"
    fi
    local perm_ok="true" detail=""
    if [ -f /etc/crontab ]; then
        local perm
        perm=$(cis_file_perm /etc/crontab)
        if ! cis_perm_le "$perm" "600"; then
            perm_ok="false"
            detail="/etc/crontab 권한 ${perm}(권장 600 이하) "
        fi
    fi
    if [ "$cron_active" = "true" ] && [ "$perm_ok" = "true" ]; then
        cis_record_result "CL-32" "PASS" "cron 활성화 및 crontab 권한 적정"
    elif [ "$cron_active" = "false" ]; then
        cis_record_result "CL-32" "REVIEW" "cron 데몬이 비활성화됨 — 미사용 시 정상 ${detail}"
    else
        cis_record_result "CL-32" "FAIL" "crontab 권한 미흡: ${detail}"
    fi
}

check_CL_33() {
    cis_print_check "CL-33"
    local issues=""
    [ -f /etc/cron.deny ] && issues="${issues}cron.deny존재 "
    [ -f /etc/at.deny ] && issues="${issues}at.deny존재 "
    [ -f /etc/cron.allow ] || issues="${issues}cron.allow없음 "
    [ -f /etc/at.allow ] || issues="${issues}at.allow없음 "
    if [ -z "$issues" ]; then
        cis_record_result "CL-33" "PASS" "cron.allow/at.allow 화이트리스트 적용됨"
    else
        cis_record_result "CL-33" "FAIL" "cron/at 접근 제한 미흡: ${issues}"
    fi
}

check_CL_34() {
    cis_print_check "CL-34"
    if [ ! -f /etc/ssh/sshd_config ]; then
        cis_record_result "CL-34" "REVIEW" "sshd_config가 없음 (SSH 미설치 가능성)"
        return
    fi
    local perm owner
    perm=$(cis_file_perm /etc/ssh/sshd_config)
    owner=$(cis_file_owner /etc/ssh/sshd_config)
    # sshd_config엔 비밀정보가 없고 644/root:root는 대다수 배포판 기본값이므로 양호로 인정.
    # 600 이하는 참고용 강화 권고로만 안내한다.
    if cis_perm_le "$perm" "644" && [ "$owner" = "root" ]; then
        if cis_perm_le "$perm" "600"; then
            cis_record_result "CL-34" "PASS" "sshd_config 권한 ${perm}, 소유자 ${owner}"
        else
            cis_record_result "CL-34" "PASS" "sshd_config 권한 ${perm}(배포판 기본값), 소유자 ${owner} — 600으로 강화 권고(선택)"
        fi
    else
        cis_record_result "CL-34" "FAIL" "sshd_config 권한/소유자 미흡 (권한:${perm}, 소유자:${owner}, 최대 권장:644)"
    fi
}

check_CL_35() {
    cis_print_check "CL-35"
    if [ ! -f /etc/ssh/sshd_config ]; then
        cis_record_result "CL-35" "REVIEW" "sshd_config가 없음 (SSH 미설치 가능성)"
        return
    fi
    local val
    val=$(_cis_sshd_get "PermitRootLogin")
    if [ "$val" = "no" ]; then
        cis_record_result "CL-35" "PASS" "PermitRootLogin no — root 직접 로그인 차단"
    elif [ -z "$val" ]; then
        cis_record_result "CL-35" "REVIEW" "PermitRootLogin 미명시 (기본값 의존) — 명시적 no 권장"
    else
        cis_record_result "CL-35" "FAIL" "PermitRootLogin ${val} — root 직접 로그인 허용"
    fi
}

check_CL_36() {
    cis_print_check "CL-36"
    if [ ! -f /etc/ssh/sshd_config ]; then
        cis_record_result "CL-36" "REVIEW" "sshd_config가 없음 (SSH 미설치 가능성)"
        return
    fi
    local issues=""
    local empty maxauth x11
    empty=$(_cis_sshd_get "PermitEmptyPasswords")
    [ "$empty" = "yes" ] && issues="${issues}PermitEmptyPasswords=yes "
    maxauth=$(_cis_sshd_get "MaxAuthTries")
    if [ -n "$maxauth" ] && [ "$maxauth" -gt 4 ] 2>/dev/null; then
        issues="${issues}MaxAuthTries=${maxauth}(>4) "
    fi
    x11=$(_cis_sshd_get "X11Forwarding")
    [ "$x11" = "yes" ] && issues="${issues}X11Forwarding=yes "
    if [ -z "$issues" ]; then
        cis_record_result "CL-36" "PASS" "SSH 보안 옵션이 적정하게 설정됨"
    else
        cis_record_result "CL-36" "FAIL" "취약한 SSH 옵션: ${issues}"
    fi
}

check_CL_37() {
    cis_print_check "CL-37"
    if [ ! -f /etc/login.defs ]; then
        cis_record_result "CL-37" "REVIEW" "/etc/login.defs가 없어 점검 불가"
        return
    fi
    local maxd mind warn
    maxd=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    mind=$(grep -E "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    warn=$(grep -E "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}')
    local issues=""
    { [ -z "$maxd" ] || [ "$maxd" -gt 90 ] 2>/dev/null; } && issues="${issues}MAX_DAYS=${maxd:-미설정}(권장≤90) "
    { [ -z "$mind" ] || [ "$mind" -lt 1 ] 2>/dev/null; } && issues="${issues}MIN_DAYS=${mind:-미설정}(권장≥1) "
    { [ -z "$warn" ] || [ "$warn" -lt 7 ] 2>/dev/null; } && issues="${issues}WARN_AGE=${warn:-미설정}(권장≥7) "
    if [ -z "$issues" ]; then
        cis_record_result "CL-37" "PASS" "패스워드 만료 정책 적정 (MAX=${maxd}, MIN=${mind}, WARN=${warn})"
    else
        cis_record_result "CL-37" "FAIL" "패스워드 정책 미흡: ${issues}"
    fi
}

check_CL_38() {
    cis_print_check "CL-38"
    if ! cis_command_exists sudo; then
        cis_record_result "CL-38" "REVIEW" "sudo가 설치되어 있지 않음"
        return
    fi
    local use_pty="false" logfile="false"
    if grep -rqE "^\s*Defaults\s+.*use_pty" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        use_pty="true"
    fi
    if grep -rqE "^\s*Defaults\s+.*logfile\s*=" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        logfile="true"
    fi
    if [ "$use_pty" = "true" ] && [ "$logfile" = "true" ]; then
        cis_record_result "CL-38" "PASS" "sudo use_pty 및 logfile 설정됨"
    else
        cis_record_result "CL-38" "FAIL" "sudo 보안 설정 미흡 (use_pty=${use_pty}, logfile=${logfile})"
    fi
}
