#!/bin/bash
# 섹션 3: 네트워크 설정 (CL-18 ~ CL-26)

# sysctl 값이 기대값과 일치하는지 점검하는 헬퍼
_cis_sysctl_check() {
    local code="$1" key="$2" expected="$3" good_msg="$4" bad_msg="$5"
    local val
    val=$(cis_sysctl_get "$key")
    if [ -z "$val" ]; then
        cis_record_result "$code" "REVIEW" "${key} 값을 확인할 수 없음"
    elif [ "$val" = "$expected" ]; then
        cis_record_result "$code" "PASS" "${good_msg} (${key}=${val})"
    else
        cis_record_result "$code" "FAIL" "${bad_msg} (${key}=${val}, 권장:${expected})"
    fi
}

check_CL_18() {
    cis_print_check "CL-18"
    _cis_sysctl_check "CL-18" "net.ipv4.ip_forward" "0" \
        "IP 포워딩 비활성화됨" "IP 포워딩이 활성화됨"
}

check_CL_19() {
    cis_print_check "CL-19"
    _cis_sysctl_check "CL-19" "net.ipv4.conf.all.send_redirects" "0" \
        "패킷 리다이렉트 전송 비활성화됨" "리다이렉트 전송이 활성화됨"
}

check_CL_20() {
    cis_print_check "CL-20"
    _cis_sysctl_check "CL-20" "net.ipv4.conf.all.accept_source_route" "0" \
        "Source Routed 패킷 미수용" "Source Routed 패킷을 수용함"
}

check_CL_21() {
    cis_print_check "CL-21"
    _cis_sysctl_check "CL-21" "net.ipv4.conf.all.accept_redirects" "0" \
        "ICMP 리다이렉트 미수용" "ICMP 리다이렉트를 수용함"
}

check_CL_22() {
    cis_print_check "CL-22"
    _cis_sysctl_check "CL-22" "net.ipv4.conf.all.log_martians" "1" \
        "비정상 패킷 로깅 활성화됨" "비정상 패킷 로깅이 비활성화됨"
}

check_CL_23() {
    cis_print_check "CL-23"
    _cis_sysctl_check "CL-23" "net.ipv4.icmp_echo_ignore_broadcasts" "1" \
        "브로드캐스트 ICMP 무시함" "브로드캐스트 ICMP에 응답함"
}

check_CL_24() {
    cis_print_check "CL-24"
    # rp_filter는 0(비활성)/1(strict)/2(loose) 3단계 값이라 범용 sysctl 비교로는
    # loose(2, 켜짐)를 "비활성화"로 오기재하므로 값별로 별도 판정한다.
    local val
    val=$(cis_sysctl_get "net.ipv4.conf.all.rp_filter")
    if [ -z "$val" ]; then
        cis_record_result "CL-24" "REVIEW" "net.ipv4.conf.all.rp_filter 값을 확인할 수 없음"
    elif [ "$val" = "1" ]; then
        cis_record_result "CL-24" "PASS" "Reverse Path Filtering strict 모드로 활성화됨 (rp_filter=1)"
    elif [ "$val" = "2" ]; then
        cis_record_result "CL-24" "REVIEW" "Reverse Path Filtering loose 모드로 활성화됨 — 비활성 아님, CIS 권장 strict(1)로 전환 검토 (rp_filter=2)"
    else
        cis_record_result "CL-24" "FAIL" "Reverse Path Filtering이 비활성화됨 (rp_filter=${val}, 권장:1)"
    fi
}

check_CL_25() {
    cis_print_check "CL-25"
    _cis_sysctl_check "CL-25" "net.ipv4.tcp_syncookies" "1" \
        "TCP SYN 쿠키 활성화됨" "TCP SYN 쿠키가 비활성화됨"
}

check_CL_26() {
    cis_print_check "CL-26"
    # ufw
    if cis_command_exists ufw; then
        if ufw status 2>/dev/null | grep -qi "Status: active"; then
            cis_record_result "CL-26" "PASS" "ufw 방화벽 활성화됨"
            return
        fi
    fi
    # firewalld
    if cis_command_exists firewall-cmd; then
        if firewall-cmd --state 2>/dev/null | grep -qi running; then
            cis_record_result "CL-26" "PASS" "firewalld 방화벽 활성화됨"
            return
        fi
    fi
    # nftables
    if cis_command_exists nft; then
        if [ -n "$(nft list ruleset 2>/dev/null)" ]; then
            cis_record_result "CL-26" "PASS" "nftables 규칙이 설정됨"
            return
        fi
    fi
    # iptables
    if cis_command_exists iptables; then
        local rules
        rules=$(iptables -S 2>/dev/null | grep -vE "^-P (INPUT|FORWARD|OUTPUT) ACCEPT" | grep -c "^-")
        if [ "${rules:-0}" -gt 0 ] 2>/dev/null; then
            cis_record_result "CL-26" "PASS" "iptables 규칙이 설정됨 (${rules}개)"
            return
        fi
    fi
    cis_record_result "CL-26" "FAIL" "호스트 방화벽이 활성화되어 있지 않음"
}
