#!/bin/bash
################################################################################
# U-30: 기본 계정 보안 설정
################################################################################
check_U_30() {
    print_security_check "U-30" "기본 계정 보안 설정" 1

    local active_accounts=""
    local default_accounts=("bin" "daemon" "adm" "lp" "sync" "shutdown" "halt" "mail" "nobody")

    for acct in "${default_accounts[@]}"; do
        if id "$acct" &>/dev/null; then
            local lock_status
            lock_status=$(is_account_locked "$acct")
            local shell
            shell=$(get_shell "$acct")
            local nologin
            nologin=$(is_nologin_shell "$shell")
            if [ "$lock_status" = "unlocked" ] && [ "$nologin" = "false" ]; then
                append_log "  기본 계정 ${acct}이 잠금 해제 상태이고 로그인 가능한 쉘 사용"
                active_accounts="${active_accounts:+${active_accounts}, }${acct}(${shell})"
            fi
        fi
    done

    if [ -n "$active_accounts" ]; then
        record_check_result "U-30" "FAIL" "잠금 해제 상태이고 로그인 가능한 기본 계정 존재: ${active_accounts}"
    else
        record_check_result "U-30" "PASS" "기본 계정이 적절히 비활성화됨"
    fi
}
