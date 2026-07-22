#!/bin/bash
################################################################################
# U-67: 로그 디렉터리 소유자 및 권한 설정
################################################################################
check_U_67() {
    print_security_check "U-67" "로그 디렉터리 소유자 및 권한 설정" 1

    local fail=false
    local issues=""

    if [ ! -d /var/log ]; then
        record_check_result "U-67" "REVIEW" "/var/log 디렉토리 없음"
        return
    fi

    local perm owner
    perm=$(stat -c %a /var/log 2>/dev/null || stat -f %Lp /var/log 2>/dev/null)
    owner=$(stat -c %U /var/log 2>/dev/null || stat -f %Su /var/log 2>/dev/null)
    perm=$(echo "$perm" | tr -d '[:space:]' | sed 's/^0*//')
    append_log "  /var/log: 권한=${perm}, 소유자=${owner}"

    if [ "$owner" != "root" ]; then
        append_log "  ⚠️  /var/log 소유자가 root가 아님: ${owner}"
        issues="${issues:+${issues} / }/var/log 소유자=${owner}(권장 root)"
        fail=true
    fi

    # world-writable 확인
    if [ "$(printf '%d' "0${perm}")" -gt "$(printf '%d' 0755)" ] 2>/dev/null; then
        append_log "  ⚠️  /var/log 권한이 755 초과"
        issues="${issues:+${issues} / }/var/log 권한=${perm}(최대 755)"
        fail=true
    fi

    # 주요 로그 파일 권한 확인
    # wtmp/btmp는 who/w/last 등이 utmp 그룹으로 읽어야 해서 root:utmp 664/660이
    # Debian/Ubuntu 표준이므로, 이 조합만 별도로 최대 664까지 허용한다.
    for f in /var/log/wtmp /var/log/btmp /var/log/auth.log /var/log/secure /var/log/messages /var/log/syslog; do
        [ -f "$f" ] || continue
        local fperm fowner fgroup
        fperm=$(stat -c %a "$f" 2>/dev/null || stat -f %Lp "$f" 2>/dev/null)
        fowner=$(stat -c %U "$f" 2>/dev/null || stat -f %Su "$f" 2>/dev/null)
        fgroup=$(stat -c %G "$f" 2>/dev/null || stat -f %Sg "$f" 2>/dev/null)
        fperm=$(echo "$fperm" | tr -d '[:space:]' | sed 's/^0*//')
        append_log "  $f: 권한=${fperm}, 소유자=${fowner}, 그룹=${fgroup}"
        case "$f" in
            */wtmp|*/btmp)
                if [ "$fgroup" = "utmp" ] && [ "$(printf '%d' "0${fperm}")" -le "$(printf '%d' 0664)" ] 2>/dev/null; then
                    continue
                elif [ "$(printf '%d' "0${fperm}")" -gt "$(printf '%d' 0640)" ] 2>/dev/null; then
                    append_log "  ⚠️  $f 권한 초과 (표준: root:utmp 664 이하 또는 640 이하)"
                    issues="${issues:+${issues} / }${f} 권한=${fperm}:${fgroup}(표준 root:utmp≤664 또는 ≤640)"
                    fail=true
                fi
                ;;
            *)
                if [ "$(printf '%d' "0${fperm}")" -gt "$(printf '%d' 0640)" ] 2>/dev/null; then
                    append_log "  ⚠️  $f 권한이 640 초과"
                    issues="${issues:+${issues} / }${f} 권한=${fperm}(최대 640)"
                    fail=true
                fi
                ;;
        esac
    done

    if $fail; then
        record_check_result "U-67" "FAIL" "로그 디렉토리/파일 권한 설정 미흡: ${issues}"
    else
        record_check_result "U-67" "PASS" "로그 디렉토리/파일 권한 설정 양호"
    fi
}
