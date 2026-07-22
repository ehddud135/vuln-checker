#!/bin/bash
################################################################################
# U-25: world writable 파일 점검
################################################################################
check_U_25() {
    print_security_check "U-25" "world writable 파일 점검" 1

    # 시스템 경로만 검사한다. /home, /root 등 사용자 영역(패키지매니저 캐시 등)을
    # 전체 스캔에 포함하면 개인 캐시 파일이 대량 오탐되므로 제외한다.
    # /tmp, /var/tmp는 sticky bit(1777)로 보호되는 정상적인 world-writable 영역이라 별도 제외.
    local scan_dirs=() d
    for d in /etc /usr /var /bin /sbin /lib /lib64 /boot /opt; do
        [ -d "$d" ] && scan_dirs+=("$d")
    done

    append_log "  world writable 파일 검색 중 (시스템 경로 한정: ${scan_dirs[*]})..."
    local ww_files
    ww_files=$(find "${scan_dirs[@]}" -xdev -perm -002 -not -type l -not -type d 2>/dev/null \
        | grep -v -E '^/(var/)?tmp/' | head -20)

    if [ -n "$ww_files" ]; then
        append_log "  발견된 world writable 파일 (상위 20개):"
        echo "$ww_files" | while read -r f; do
            append_log "    $f"
        done
        record_check_result "U-25" "FAIL" "시스템 경로 내 world writable 파일 존재"
    else
        record_check_result "U-25" "PASS" "시스템 경로 내 world writable 파일 없음 (사용자 홈·/tmp 제외)"
    fi
}
