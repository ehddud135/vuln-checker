#!/bin/bash
################################################################################
# U-04: 비밀번호 파일 보호
################################################################################
check_U_04() {
    print_security_check "U-04" "비밀번호 파일 보호" 1

    local issues=""

    # /etc/passwd: max 644, owner root
    if [ -f /etc/passwd ]; then
        local perm owner
        perm=$(stat -c %a /etc/passwd 2>/dev/null || stat -f %Lp /etc/passwd 2>/dev/null)
        owner=$(stat -c %U /etc/passwd 2>/dev/null || stat -f %Su /etc/passwd 2>/dev/null)
        perm=$(echo "$perm" | tr -d '[:space:]' | sed 's/^0*//')
        append_log "  /etc/passwd: 권한=${perm}, 소유자=${owner}"
        if [ "$owner" != "root" ] || [ "$(printf '%d' "0${perm}")" -gt "$(printf '%d' 0644)" ] 2>/dev/null; then
            append_log "  /etc/passwd 권한 부적절 (권장: 644, root 소유)"
            issues="${issues:+${issues} / }/etc/passwd 권한=${perm},소유자=${owner}(권장 644 root)"
        fi
    fi

    # /etc/shadow: max 400, owner root
    if [ -f /etc/shadow ]; then
        local perm owner
        perm=$(stat -c %a /etc/shadow 2>/dev/null || stat -f %Lp /etc/shadow 2>/dev/null)
        owner=$(stat -c %U /etc/shadow 2>/dev/null || stat -f %Su /etc/shadow 2>/dev/null)
        perm=$(echo "$perm" | tr -d '[:space:]' | sed 's/^0*//')
        append_log "  /etc/shadow: 권한=${perm}, 소유자=${owner}"
        if [ "$owner" != "root" ] || [ "$(printf '%d' "0${perm}")" -gt "$(printf '%d' 0400)" ] 2>/dev/null; then
            append_log "  /etc/shadow 권한 부적절 (권장: 400, root 소유)"
            issues="${issues:+${issues} / }/etc/shadow 권한=${perm},소유자=${owner}(권장 400 root)"
        fi
    fi

    if [ -n "$issues" ]; then
        record_check_result "U-04" "FAIL" "비밀번호 파일 권한 설정 미흡: ${issues}"
    else
        record_check_result "U-04" "PASS" "비밀번호 파일 권한 적절히 설정됨"
    fi
}
