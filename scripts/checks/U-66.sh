#!/bin/bash
################################################################################
# U-66: 정책에 따른 시스템 로깅 설정
################################################################################
check_U_66() {
    print_security_check "U-66" "정책에 따른 시스템 로깅 설정" 1

    local fail=false
    local logging_active=false

    # rsyslog 확인
    if command_exists systemctl; then
        local rsyslog_status
        rsyslog_status=$(systemctl is-active rsyslog 2>/dev/null)
        append_log "  rsyslog 상태: ${rsyslog_status:-알 수 없음}"
        [ "$rsyslog_status" = "active" ] && logging_active=true
    fi

    # syslog 확인
    if command_exists systemctl; then
        local syslog_status
        syslog_status=$(systemctl is-active syslog 2>/dev/null)
        append_log "  syslog 상태: ${syslog_status:-알 수 없음}"
        [ "$syslog_status" = "active" ] && logging_active=true
    fi

    # journald 확인 (systemd)
    if command_exists journalctl; then
        local journal_status
        journal_status=$(systemctl is-active systemd-journald 2>/dev/null)
        append_log "  systemd-journald 상태: ${journal_status:-알 수 없음}"
        [ "$journal_status" = "active" ] && logging_active=true
    fi

    # /var/log 주요 로그 파일 확인 (전통적 flat-file 로깅 여부)
    local log_files=("/var/log/auth.log" "/var/log/secure" "/var/log/messages" "/var/log/syslog")
    local log_found=false
    for f in "${log_files[@]}"; do
        if [ -f "$f" ]; then
            append_log "  로그 파일 존재: $f"
            log_found=true
        fi
    done

    # journald 영구 저장(/var/log/journal)도 유효한 로그 보관으로 인정
    # (rsyslog 없이 journald만 쓰는 배포판에서 클래식 로그 파일이 없을 수 있음)
    local journal_volatile_only=false
    if ! $log_found && [ -d /var/log/journal ]; then
        append_log "  journald 영구 저장 사용 중: /var/log/journal"
        log_found=true
    elif ! $log_found && [ -d /run/log/journal ]; then
        append_log "  ⚠️  journald가 휘발성 저장(/run/log/journal)만 사용 — 재부팅 시 로그 소실"
        journal_volatile_only=true
    fi

    local issues=""
    if ! $log_found; then
        append_log "  ⚠️  주요 로그 파일이 없음"
        if $journal_volatile_only; then
            issues="journald가 휘발성 저장만 사용(재부팅 시 소실) — /etc/systemd/journald.conf에 Storage=persistent 설정 필요"
        else
            issues="주요 로그 파일 없음"
        fi
        fail=true
    fi

    if ! $logging_active; then
        append_log "  ⚠️  로깅 서비스가 활성화되지 않음"
        issues="${issues:+${issues} / }로깅 서비스(rsyslog/journald) 비활성"
        fail=true
    fi

    if $fail; then
        record_check_result "U-66" "FAIL" "시스템 로깅 설정 미흡: ${issues}"
    else
        record_check_result "U-66" "PASS" "시스템 로깅 설정 양호"
    fi
}
