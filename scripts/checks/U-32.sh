#!/bin/bash
################################################################################
# U-32: 홈 디렉토리로 지정한 디렉토리의 존재 관리
################################################################################
check_U_32() {
    print_security_check "U-32" "홈 디렉토리로 지정한 디렉토리의 존재 관리" 1

    local missing=""
    while IFS=: read -r user _ uid _ _ home shell; do
        case "$uid" in ''|*[!0-9]*) continue ;; esac
        [ "$uid" -lt 1000 ] && continue
        [ -z "$home" ] && continue
        # 로그인 불가 계정(nobody 등)은 홈 디렉토리가 의도적으로 없을 수 있으므로 제외
        [ "$(is_nologin_shell "$shell")" = "true" ] && continue
        if [ ! -d "$home" ]; then
            missing="${missing} ${user}(${home})"
        fi
    done < /etc/passwd

    if [ -n "$missing" ]; then
        append_log "  홈 디렉토리 없는 계정:${missing}"
        record_check_result "U-32" "FAIL" "홈 디렉토리가 존재하지 않는 계정:${missing}"
    else
        record_check_result "U-32" "PASS" "모든 사용자 홈 디렉토리 존재"
    fi
}
