package collector

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CheckResultPayload mirrors the server's CheckResultInputSerializer.
type CheckResultPayload struct {
	Code             string         `json:"code"`
	Name             string         `json:"name"`
	Category         string         `json:"category"`
	Standard         string         `json:"standard"`
	Status           string         `json:"status"`
	Detail           string         `json:"detail"`
	Reference        map[string]any `json:"reference"`
	DerivedFromCodes []string       `json:"derived_from_codes"`
}

// CheckRunPayload mirrors the server's ResultsSubmitSerializer.
type CheckRunPayload struct {
	RunID         string               `json:"run_id"`
	Profile       string               `json:"profile"`
	ExecutedAt    string               `json:"executed_at"`
	ExpectedCount int                  `json:"expected_count"`
	Results       []CheckResultPayload `json:"results"`
}

// standardForFilename tags a CheckResult's standard from the SOURCE FILENAME,
// not from JSON content — individual per-standard files (result_*.json,
// docker_result_*.json, ...) don't carry a "standard" field at all, and the
// combined result_all_*.json (only produced when 2+ profiles ran) uses a
// Korean-label string. Relying on either would be fragile (Codex 교차검증:
// main.sh 실제 출력과 CheckRun/CheckResult 모델 불일치).
func standardForFilename(name string) (standard string, ok bool) {
	switch {
	case strings.HasPrefix(name, "result_all_"):
		return "", false // 통합 파일은 쓰지 않는다 — 개별 파일만 읽는다(결정됨)
	case strings.HasPrefix(name, "docker_result_"):
		return "docker", true
	case strings.HasPrefix(name, "cis_linux_result_"):
		return "cis-linux", true
	case strings.HasPrefix(name, "isms_p_result_"):
		return "isms-p", true
	case strings.HasPrefix(name, "result_"):
		return "kisa", true
	default:
		return "", false
	}
}

type rawCheck struct {
	Code      string         `json:"code"`
	Name      string         `json:"name"`
	Category  string         `json:"category"`
	Status    string         `json:"status"`
	Detail    string         `json:"detail"`
	Reference map[string]any `json:"reference"`
}

// resultFileStaleWindow is the tolerance for deciding which result files
// belong to this invocation of main.sh vs a stale leftover from a previous run.
const resultFileStaleWindow = 2 * time.Second

type rawFile struct {
	Summary struct {
		Total int `json:"total"`
	} `json:"summary"`
	Checks []rawCheck `json:"checks"`
}

// generateRunID is created BEFORE main.sh executes, per Codex 교차검증:
// idempotency는 실행 시작 시점에 만든 run ID를 디스크에 영속화해야 한다 — 결과
// 파일을 다시 읽어 새 키를 만들면 재전송 시 중복 방지가 깨진다.
func generateRunID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("run-%d-%x", time.Now().UnixNano(), buf), nil
}

// RunChecks shells out to the existing bash checker (never reimplemented —
// design doc Constraint) and parses whichever per-standard JSON files it
// produced during this invocation.
func RunChecks(mainShPath, resultsDir, profile string) (*CheckRunPayload, error) {
	runID, err := generateRunID()
	if err != nil {
		return nil, fmt.Errorf("generate run id: %w", err)
	}

	startedAt := time.Now()

	// 절대경로로 정규화 — cmd.Dir을 설정한 채로 상대경로 Path를 넘기면 Go가
	// 그 상대경로를 호출자의 cwd가 아니라 cmd.Dir 기준으로 다시 해석해
	// 엉뚱한 경로가 되는 문제가 있다.
	absMainSh, err := filepath.Abs(mainShPath)
	if err != nil {
		return nil, fmt.Errorf("resolve main.sh path: %w", err)
	}
	cmd := exec.Command(absMainSh, "--profile", profile)
	cmd.Dir = filepath.Dir(absMainSh)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("main.sh 실행 실패: %w\n%s", err, string(output))
	}

	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		return nil, fmt.Errorf("read results dir: %w", err)
	}

	var candidateFiles []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		// 이번 실행에서 생성된 파일만 취급한다 (이전 실행의 stale 파일을 잘못 집지 않도록)
		if info.ModTime().Before(startedAt.Add(-resultFileStaleWindow)) {
			continue
		}
		if _, ok := standardForFilename(e.Name()); ok {
			candidateFiles = append(candidateFiles, e.Name())
		}
	}
	sort.Strings(candidateFiles)

	var results []CheckResultPayload
	expectedCount := 0

	for _, filename := range candidateFiles {
		standard, _ := standardForFilename(filename)
		data, err := os.ReadFile(filepath.Join(resultsDir, filename))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filename, err)
		}
		var parsed rawFile
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, fmt.Errorf("parse %s: %w", filename, err)
		}
		expectedCount += parsed.Summary.Total

		for _, c := range parsed.Checks {
			results = append(results, CheckResultPayload{
				Code:      c.Code,
				Name:      c.Name,
				Category:  c.Category,
				Standard:  standard,
				Status:    c.Status,
				Detail:    c.Detail,
				Reference: c.Reference,
				// ISMS-P의 derived_from_codes(매핑된 U-XX 코드) 채우기는 Phase 1
				// 스코프 밖 — isms-p/scripts/mapping.sh의 매핑 테이블을 별도로
				// 파싱해야 하므로 이후 Phase에서 다룬다. 지금은 항상 빈 값.
				DerivedFromCodes: []string{},
			})
		}
	}

	return &CheckRunPayload{
		RunID:         runID,
		Profile:       profile,
		ExecutedAt:    startedAt.UTC().Format(time.RFC3339),
		ExpectedCount: expectedCount,
		Results:       results,
	}, nil
}
