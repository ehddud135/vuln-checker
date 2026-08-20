package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"encoding/json"
	"path/filepath"

	"github.com/zeroboat/vuln-checker/agent/internal/client"
	"github.com/zeroboat/vuln-checker/agent/internal/collector"
	"github.com/zeroboat/vuln-checker/agent/internal/config"
	"github.com/zeroboat/vuln-checker/agent/internal/metrics"
	"github.com/zeroboat/vuln-checker/agent/internal/queue"
)

const (
	resultsQueueKind   = "results"
	resultsQueueMaxAge = 7 * 24 * time.Hour // 서버가 일주일 넘게 안 돌아오면 오래된 결과는 버린다
	resultsQueueMax    = 200                // 체크 주기가 하루~주 단위라 200개면 수백 일치 여유
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "enroll":
		cmdEnroll(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("사용법:")
	fmt.Println("  agent enroll --server URL --code CODE --hostname NAME [--os OS] [--distro DISTRO] --config PATH")
	fmt.Println("  agent run --config PATH --main-sh PATH --results-dir DIR [--profile all] [--once] [--check-interval 24h] [--metrics-interval 30s]")
}

// warnIfInsecureURL은 서버 URL이 https가 아니면 경고한다 — 토큰(Authorization: Token
// ...)과 점검 결과(감사 로그에 남는 설정값 등)가 평문으로 전송된다는 뜻이다. 로컬
// 개발(http://127.0.0.1 등)은 흔한 패턴이라 막지는 않고, 눈에 띄게 경고만 한다
// (adversarial review 지적 — plan.md는 HTTPS 필수라고 명시하지만 코드가 강제하지 않았음).
func warnIfInsecureURL(serverURL string) {
	if !strings.HasPrefix(serverURL, "https://") {
		log.Printf("경고: --server가 https가 아닙니다(%s) — 토큰과 점검 결과가 평문으로 전송됩니다. 운영 배포에서는 TLS 종료 리버스 프록시 뒤에 두세요.", serverURL)
	}
}

func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	server := fs.String("server", "", "서버 URL (예: https://vuln-checker.example.com — 운영에서는 반드시 https, 로컬 테스트만 http 허용)")
	code := fs.String("code", "", "1회용 등록 코드")
	hostname := fs.String("hostname", "", "호스트 이름")
	osName := fs.String("os", "", "OS (LINUX/MACOS)")
	distro := fs.String("distro", "", "배포판")
	configPath := fs.String("config", "agent.json", "설정 파일 저장 경로")
	fs.Parse(args)

	if *server == "" || *code == "" || *hostname == "" {
		log.Fatal("--server, --code, --hostname은 필수입니다")
	}
	warnIfInsecureURL(*server)

	c := client.New(*server, "", 0)
	resp, err := c.Enroll(*code, *hostname, *osName, *distro)
	if err != nil {
		log.Fatalf("등록 실패: %v", err)
	}

	cfg := &config.AgentConfig{ServerURL: *server, HostID: resp.HostID, Token: resp.Token}
	if err := config.Save(*configPath, cfg); err != nil {
		log.Fatalf("설정 저장 실패: %v", err)
	}
	fmt.Printf("등록 완료 — host_id=%d, 설정 저장 위치: %s\n", resp.HostID, *configPath)
	fmt.Printf("호스트 그룹 정책 — 점검 주기: %ds, 메트릭 주기: %ds ('agent run' 실행 시 적용, 하트비트마다 갱신됨)\n",
		resp.Policy.CheckIntervalSeconds, resp.Policy.MetricsIntervalSeconds)
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "agent.json", "설정 파일 경로")
	mainSh := fs.String("main-sh", "", "main.sh 절대경로")
	resultsDir := fs.String("results-dir", "", "main.sh가 결과 JSON을 쓰는 디렉토리")
	profile := fs.String("profile", "all", "점검 프로파일")
	once := fs.Bool("once", false, "한 번만 실행하고 종료(테스트용) — 실제 운영에서는 이중 스케줄러로 상주")
	checkInterval := fs.Duration("check-interval", 24*time.Hour, "전체 점검 주기 (무겁고 root 필요 — 하루~주 단위)")
	metricsInterval := fs.Duration("metrics-interval", 30*time.Second, "인프라 메트릭 수집 주기 (살아있는 대시보드의 핵심 — 초~분 단위)")
	fs.Parse(args)

	if *mainSh == "" || *resultsDir == "" {
		log.Fatal("--main-sh, --results-dir는 필수입니다")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("설정 로드 실패 (먼저 'agent enroll'을 실행하세요): %v", err)
	}
	warnIfInsecureURL(cfg.ServerURL)
	c := client.New(cfg.ServerURL, cfg.Token, cfg.HostID)

	// 호스트 그룹별 점검·메트릭 주기 정책(Phase 6) — CLI 플래그는 서버에 아직
	// 한 번도 연결 못 했을 때의 기본값이고, enroll/heartbeat 응답이 오면 그걸로
	// 갱신한다. 재등록 없이 정책 변경을 반영하는 게 핵심이라 값만 바꾸는 게 아니라
	// 이미 돌고 있는 티커도 Reset()한다.
	currentCheckInterval := *checkInterval
	currentMetricsInterval := *metricsInterval
	var checkTicker, metricsTicker *time.Ticker

	applyPolicy := func(p client.Policy) {
		if p.CheckIntervalSeconds > 0 {
			newInterval := time.Duration(p.CheckIntervalSeconds) * time.Second
			if newInterval != currentCheckInterval {
				log.Printf("점검 주기 정책 변경: %s -> %s", currentCheckInterval, newInterval)
				currentCheckInterval = newInterval
				if checkTicker != nil {
					checkTicker.Reset(currentCheckInterval)
				}
			}
		}
		if p.MetricsIntervalSeconds > 0 {
			newInterval := time.Duration(p.MetricsIntervalSeconds) * time.Second
			if newInterval != currentMetricsInterval {
				log.Printf("메트릭 주기 정책 변경: %s -> %s", currentMetricsInterval, newInterval)
				currentMetricsInterval = newInterval
				if metricsTicker != nil {
					metricsTicker.Reset(currentMetricsInterval)
				}
			}
		}
	}

	q, err := queue.New(filepath.Join(filepath.Dir(*configPath), "queue"))
	if err != nil {
		log.Fatalf("재시도 큐 초기화 실패: %v", err)
	}

	// flushResultsQueue는 결과 페이지의 idempotency(run_id)를 그대로 신뢰한다 —
	// 여기서 새 키를 만들지 않고 디스크에 있던 페이로드를 그대로 재전송한다.
	// 큐에 쌓인 순서(파일명 = 생성 시각)대로 보내고, 하나라도 실패하면 그 뒤는
	// 순서를 흩뜨리지 않기 위해 이번 라운드는 중단한다.
	flushResultsQueue := func() {
		pending, err := q.Pending(resultsQueueKind)
		if err != nil {
			log.Printf("재시도 큐 조회 실패: %v", err)
			return
		}
		for _, path := range pending {
			data, err := q.Load(path)
			if err != nil {
				log.Printf("재시도 큐 항목 로드 실패(%s): %v", path, err)
				continue
			}
			var run collector.CheckRunPayload
			if err := json.Unmarshal(data, &run); err != nil {
				// 손상된 큐 파일 — 영원히 막히지 않도록 버리고 계속 진행
				log.Printf("재시도 큐 항목 파싱 실패, 버림(%s): %v", path, err)
				_ = q.Remove(path)
				continue
			}
			if err := c.PostResults(&run); err != nil {
				log.Printf("재시도 실패, 다음 기회에 다시 시도 (run_id=%s): %v", run.RunID, err)
				return // 서버가 아직 안 돌아온 것으로 보고 이번 라운드는 중단
			}
			_ = q.Remove(path)
			log.Printf("재시도 큐 항목 전송 성공 (run_id=%s)", run.RunID)
		}
	}

	runCheckCycle := func() {
		flushResultsQueue()

		log.Printf("점검 실행 중 (profile=%s)...", *profile)
		run, err := collector.RunChecks(*mainSh, *resultsDir, *profile)
		if err != nil {
			log.Printf("점검 실행 실패: %v", err)
			return
		}
		if err := c.PostResults(run); err != nil {
			log.Printf("결과 전송 실패, 재시도 큐에 영속화 (run_id=%s): %v", run.RunID, err)
			if qerr := q.Enqueue(resultsQueueKind, run.RunID, run); qerr != nil {
				log.Printf("재시도 큐 저장 실패 — 이 결과는 유실됨 (run_id=%s): %v", run.RunID, qerr)
				return
			}
			if dropped, _ := q.Prune(resultsQueueKind, resultsQueueMax, resultsQueueMaxAge); dropped > 0 {
				log.Printf("재시도 큐 용량 초과로 %d개 항목 폐기", dropped)
			}
			return
		}
		log.Printf("점검 완료: %d개 결과 전송 (run_id=%s)", len(run.Results), run.RunID)
	}

	runMetricsCycle := func() {
		samples, err := metrics.CollectCPU()
		if err != nil {
			log.Printf("메트릭 수집 실패: %v", err)
			return
		}
		if err := c.PostMetrics(samples); err != nil {
			log.Printf("메트릭 전송 실패: %v", err)
			return
		}
	}

	runHeartbeat := func() {
		resp, err := c.PostHeartbeat()
		if err != nil {
			log.Printf("하트비트 실패: %v", err)
			return
		}
		applyPolicy(resp.Policy)
		// 하트비트가 성공했다는 건 서버가 살아있다는 뜻 — 체크 주기(하루~주)까지
		// 기다리지 않고 이 타이밍에 재시도 큐를 비워본다.
		flushResultsQueue()
	}

	if *once {
		runCheckCycle()
		runMetricsCycle()
		runHeartbeat()
		return
	}

	// 이중 스케줄러 — 하나로 합치지 않는다(design doc/plan.md 결정):
	// 메트릭은 초~분 단위, 전체 점검은 하루~주 단위로 완전히 독립적인 티커를 쓴다.
	// 하나의 티커로 묶으면 메트릭이 점검 주기만큼만 갱신되어 실시간성이 무력화된다.
	checkTicker = time.NewTicker(currentCheckInterval)
	metricsTicker = time.NewTicker(currentMetricsInterval)
	heartbeatTicker := time.NewTicker(1 * time.Minute)
	defer checkTicker.Stop()
	defer metricsTicker.Stop()
	defer heartbeatTicker.Stop()

	log.Printf("에이전트 시작 — check-interval=%s, metrics-interval=%s", currentCheckInterval, currentMetricsInterval)
	runCheckCycle()
	runMetricsCycle()
	runHeartbeat()

	for {
		select {
		case <-checkTicker.C:
			runCheckCycle()
		case <-metricsTicker.C:
			runMetricsCycle()
		case <-heartbeatTicker.C:
			runHeartbeat()
		}
	}
}
