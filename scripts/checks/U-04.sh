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

    # /etc/shadow: 400 root 단독소유, 또는 배포판 표준인 640 root:shadow까지 허용
    if [ -f /etc/shadow ]; then
        local shadow_detail
        shadow_detail=$(shadow_permission_detail /etc/shadow)
        append_log "  ${shadow_detail}"
        if ! shadow_permission_ok /etc/shadow; then
            append_log "  /etc/shadow 권한 부적절 (권장: 400 root 단독소유 또는 640 root:shadow)"
            issues="${issues:+${issues} / }${shadow_detail}(권장 400 root 단독 또는 640 root:shadow)"
        fi
    fi

    if [ -n "$issues" ]; then
        record_check_result "U-04" "FAIL" "비밀번호 파일 권한 설정 미흡: ${issues}"
    else
        record_check_result "U-04" "PASS" "비밀번호 파일 권한 적절히 설정됨"
    fi
}
