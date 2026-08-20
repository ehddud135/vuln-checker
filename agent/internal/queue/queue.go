// Package queue persists submissions the server rejected or couldn't reach,
// so a network blip doesn't silently lose a CheckRun. Design constraint
// (Codex 교차검증): idempotency는 "키 하나"로 끝나지 않는다 — run_id는 이미
// collector.RunChecks()가 실행 시작 시점에 만들어 페이로드에 박아두므로,
// 여기서는 그 페이로드를 디스크에 그대로 영속화했다가 재전송할 뿐, 새 키를
// 만들지 않는다.
package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type Queue struct {
	Dir string
}

func New(dir string) (*Queue, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create queue dir: %w", err)
	}
	return &Queue{Dir: dir}, nil
}

func (q *Queue) kindDir(kind string) string {
	return filepath.Join(q.Dir, kind)
}

// Enqueue persists payload under kind/id.json. Filenames are prefixed with a
// nanosecond timestamp so lexical sort == chronological (oldest first) —
// queued items must be retried in the order they were generated.
func (q *Queue) Enqueue(kind, id string, payload any) error {
	dir := q.kindDir(kind)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s queue dir: %w", kind, err)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	name := fmt.Sprintf("%d-%s.json", time.Now().UnixNano(), id)
	// 임시 파일에 쓰고 rename — 쓰는 도중 에이전트가 죽어도 반쪽짜리 큐 파일이 안 남는다
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write queue file: %w", err)
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

// Pending returns queued file paths for kind, oldest first.
func (q *Queue) Pending(kind string) ([]string, error) {
	dir := q.kindDir(kind)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s queue dir: %w", kind, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	paths := make([]string, len(names))
	for i, n := range names {
		paths[i] = filepath.Join(dir, n)
	}
	return paths, nil
}

func (q *Queue) Load(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (q *Queue) Remove(path string) error {
	return os.Remove(path)
}

// Prune enforces retention so a server outage of days doesn't grow the queue
// forever: drop anything older than maxAge, then drop the oldest excess
// beyond maxItems. Returns how many were dropped (always log this — a silent
// drop is exactly the kind of gap the eng review flagged).
func (q *Queue) Prune(kind string, maxItems int, maxAge time.Duration) (dropped int, err error) {
	paths, err := q.Pending(kind)
	if err != nil {
		return 0, err
	}

	cutoff := time.Now().Add(-maxAge)
	var kept []string
	for _, p := range paths {
		info, statErr := os.Stat(p)
		if statErr == nil && info.ModTime().Before(cutoff) {
			if rmErr := os.Remove(p); rmErr == nil {
				dropped++
			}
			continue
		}
		kept = append(kept, p)
	}

	if len(kept) > maxItems {
		excess := len(kept) - maxItems
		for _, p := range kept[:excess] {
			if rmErr := os.Remove(p); rmErr == nil {
				dropped++
			}
		}
	}

	return dropped, nil
}
