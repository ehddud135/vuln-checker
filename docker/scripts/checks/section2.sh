#!/bin/bash
# 섹션 2: Docker 데몬 설정 (D-08 ~ D-25)

check_D_08() {
    docker_print_check "D-08"
    local icc
    icc=$(docker network inspect bridge 2>/dev/null | \
        grep -i '"com.docker.network.bridge.enable_icc"' | \
        grep -o '"true"\|"false"' | tr -d '"')
    local daemon_icc
    daemon_icc=$(daemon_json_get "icc")
    if [ "$icc" = "false" ] || [ "$daemon_icc" = "false" ]; then
        docker_record_result "D-08" "PASS" "컨테이너 간 네트워크 통신(ICC) 비활성화됨"
    else
        docker_record_result "D-08" "FAIL" "ICC가 활성화됨 — daemon.json에 {\"icc\": false} 설정 필요"
    fi
}

check_D_09() {
    docker_print_check "D-09"
    local log_level
    log_level=$(docker info 2>/dev/null | grep -i "Logging Driver" | head -1)
    local daemon_level
    daemon_level=$(daemon_json_get "log-level")
    if [ "$daemon_level" = "info" ] || [ -z "$daemon_level" ]; then
        docker_record_result "D-09" "PASS" "로깅 레벨: ${daemon_level:-info(기본값)}"
    elif [ "$daemon_level" = "debug" ]; then
        docker_record_result "D-09" "FAIL" "로깅 레벨이 debug — info로 변경 필요"
    else
        docker_record_result "D-09" "REVIEW" "로깅 레벨: ${daemon_level} — info 권장"
    fi
}

check_D_10() {
    docker_print_check "D-10"
    local iptables_val
    iptables_val=$(daemon_json_get "iptables")
    if [ "$iptables_val" = "false" ]; then
        docker_record_result "D-10" "FAIL" "iptables가 비활성화됨 — 네트워크 격리 규칙 미적용"
    else
        docker_record_result "D-10" "PASS" "iptables 활성화됨 (기본값)"
    fi
}

check_D_11() {
    docker_print_check "D-11"
    local insecure
    # docker info는 'Insecure Registries:' 헤더를 항상 출력하고 기본값으로
    # 루프백(127.0.0.0/8, ::1/128)을 포함하므로, 실제 추가 설정된 항목만 추출한다.
    insecure=$(docker info 2>/dev/null \
        | awk '/^ Insecure Registries:$/{f=1; next} f && /^  /{print $1; next} f{exit}' \
        | grep -Ev '^(127\.0\.0\.0/8|::1/128)$')
    if [ -z "$insecure" ]; then
        docker_record_result "D-11" "PASS" "insecure-registries 설정 없음 (기본 루프백 제외)"
    else
        docker_record_result "D-11" "FAIL" "신뢰할 수 없는 레지스트리 설정 존재: $(echo "$insecure" | tr '\n' ' ')"
    fi
}

check_D_12() {
    docker_print_check "D-12"
    local storage_driver
    storage_driver=$(docker info 2>/dev/null | grep "Storage Driver" | awk '{print $3}')
    if [ "$storage_driver" = "aufs" ]; then
        docker_record_result "D-12" "FAIL" "aufs 스토리지 드라이버 사용 중 — overlay2 권장"
    else
        docker_record_result "D-12" "PASS" "스토리지 드라이버: ${storage_driver:-알 수 없음}"
    fi
}

check_D_13() {
    docker_print_check "D-13"
    # Unix 소켓만 사용하면 TLS 불필요
    local tcp_listen
    tcp_listen=$(ps aux 2>/dev/null | grep dockerd | grep -v grep | grep -E '\-H tcp://')
    if [ -n "$tcp_listen" ]; then
        local tls_verify
        tls_verify=$(ps aux 2>/dev/null | grep dockerd | grep -v grep | grep "tlsverify")
        if [ -n "$tls_verify" ]; then
            docker_record_result "D-13" "PASS" "TCP 원격 접근 활성화, TLS 인증 설정됨"
        else
            docker_record_result "D-13" "FAIL" "TCP 원격 접근이 TLS 없이 허용됨 — --tlsverify 설정 필요"
        fi
    else
        docker_record_result "D-13" "PASS" "TCP 원격 접근 없음 (Unix 소켓만 사용)"
    fi
}

check_D_14() {
    docker_print_check "D-14"
    local ulimits
    ulimits=$(docker info 2>/dev/null | grep -i "Default Ulimits" | head -1)
    local daemon_ulimits
    daemon_ulimits=$(daemon_json_get "default-ulimits")
    if [ -n "$ulimits" ] || [ -n "$daemon_ulimits" ]; then
        docker_record_result "D-14" "PASS" "기본 ulimit 설정됨: ${ulimits}"
    else
        docker_record_result "D-14" "REVIEW" "기본 ulimit 미설정 — daemon.json에 default-ulimits 설정 권장"
    fi
}

check_D_15() {
    docker_print_check "D-15"
    local userns
    userns=$(docker info 2>/dev/null | grep -i "userns" | head -1)
    local daemon_userns
    daemon_userns=$(daemon_json_get "userns-remap")
    if [ -n "$daemon_userns" ] || echo "$userns" | grep -qi "userns"; then
        docker_record_result "D-15" "PASS" "사용자 네임스페이스 재매핑 설정됨: ${daemon_userns}"
    else
        docker_record_result "D-15" "REVIEW" "userns-remap 미설정 — 컨테이너 root = 호스트 root"
    fi
}

check_D_16() {
    docker_print_check "D-16"
    local cgroup_driver
    cgroup_driver=$(docker info 2>/dev/null | grep -i "Cgroup Driver" | awk '{print $3}')
    if [ -n "$cgroup_driver" ]; then
        docker_record_result "D-16" "PASS" "cgroup 드라이버: ${cgroup_driver}"
    else
        docker_record_result "D-16" "REVIEW" "cgroup 정보 확인 불가"
    fi
}

check_D_17() {
    docker_print_check "D-17"
    local no_new_priv
    no_new_priv=$(daemon_json_get "no-new-privileges")
    if [ "$no_new_priv" = "true" ]; then
        docker_record_result "D-17" "PASS" "no-new-privileges: true 설정됨"
    else
        docker_record_result "D-17" "REVIEW" "no-new-privileges 미설정 — daemon.json에 추가 권장"
    fi
}

check_D_18() {
    docker_print_check "D-18"
    local tcp_listen
    tcp_listen=$(ps aux 2>/dev/null | grep dockerd | grep -v grep | grep -E '\-H tcp://')
    if [ -n "$tcp_listen" ]; then
        docker_record_result "D-18" "FAIL" "Docker 데몬이 TCP로 원격 접근 허용 중 — Unix 소켓만 사용 권장"
    else
        docker_record_result "D-18" "PASS" "TCP 원격 접근 없음"
    fi
}

check_D_19() {
    docker_print_check "D-19"
    local live_restore
    live_restore=$(daemon_json_get "live-restore")
    if [ "$live_restore" = "true" ]; then
        docker_record_result "D-19" "PASS" "live-restore: true 설정됨"
    else
        docker_record_result "D-19" "REVIEW" "live-restore 미설정 — daemon.json에 추가 권장"
    fi
}

check_D_20() {
    docker_print_check "D-20"
    local userland_proxy
    userland_proxy=$(daemon_json_get "userland-proxy")
    if [ "$userland_proxy" = "false" ]; then
        docker_record_result "D-20" "PASS" "userland-proxy: false 설정됨"
    else
        docker_record_result "D-20" "REVIEW" "userland-proxy 활성화(기본값) — false 설정 권장"
    fi
}

check_D_21() {
    docker_print_check "D-21"
    local experimental
    experimental=$(docker version 2>/dev/null | grep -i "Experimental" | awk '{print $2}' | head -1)
    if [ "$experimental" = "false" ] || [ -z "$experimental" ]; then
        docker_record_result "D-21" "PASS" "실험적 기능 비활성화"
    else
        docker_record_result "D-21" "FAIL" "실험적 기능 활성화됨 — daemon.json에 {\"experimental\": false} 설정"
    fi
}

check_D_22() {
    docker_print_check "D-22"
    local seccomp
    seccomp=$(docker info 2>/dev/null | grep -i "seccomp" | head -1)
    if echo "$seccomp" | grep -qi "Profile: default\|seccomp.*true\|seccomp.*active"; then
        docker_record_result "D-22" "PASS" "seccomp 기본 프로파일 적용됨"
    elif [ -n "$seccomp" ]; then
        docker_record_result "D-22" "PASS" "seccomp 설정 확인됨: ${seccomp}"
    else
        docker_record_result "D-22" "REVIEW" "seccomp 상태 확인 불가 — docker info 결과에서 직접 확인 필요"
    fi
}

check_D_23() {
    docker_print_check "D-23"
    local tcp_listen
    tcp_listen=$(ps aux 2>/dev/null | grep dockerd | grep -v grep | grep -E '\-H tcp://')
    if [ -z "$tcp_listen" ]; then
        docker_record_result "D-23" "PASS" "TCP 미사용 — TLS 인증서 불필요"
        return
    fi
    local proc_line
    proc_line=$(ps aux 2>/dev/null | grep dockerd | grep -v grep)
    local has_cacert has_cert has_key
    has_cacert=$(echo "$proc_line" | grep -c "tlscacert")
    has_cert=$(echo "$proc_line" | grep -c "tlscert")
    has_key=$(echo "$proc_line" | grep -c "tlskey")
    if [ "$has_cacert" -ge 1 ] && [ "$has_cert" -ge 1 ] && [ "$has_key" -ge 1 ]; then
        docker_record_result "D-23" "PASS" "TLS 인증서 3종(cacert, cert, key) 모두 설정됨"
    else
        docker_record_result "D-23" "FAIL" "TLS 인증서 불완전 설정 — cacert/cert/key 모두 필요"
    fi
}

check_D_24() {
    docker_print_check "D-24"
    local log_driver
    log_driver=$(docker info 2>/dev/null | grep "Logging Driver" | awk '{print $3}')
    if [ -n "$log_driver" ]; then
        docker_record_result "D-24" "PASS" "로깅 드라이버 설정됨: ${log_driver}"
    else
        docker_record_result "D-24" "REVIEW" "로깅 드라이버 확인 불가"
    fi
}

check_D_25() {
    docker_print_check "D-25"
    local wildcard_ports
    wildcard_ports=$(docker ps --format '{{.Ports}}' 2>/dev/null | grep '0\.0\.0\.0:')
    if [ -z "$wildcard_ports" ]; then
        docker_record_result "D-25" "PASS" "0.0.0.0 바인딩 포트 없음"
    else
        local count
        count=$(echo "$wildcard_ports" | grep -c '0\.0\.0\.0' || echo "0")
        docker_record_result "D-25" "REVIEW" "0.0.0.0으로 바인딩된 포트 ${count}개 — 특정 인터페이스 바인딩 권장"
    fi
}
