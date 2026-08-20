package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// AgentConfig persists the server address and the host-bound token issued
// during enrollment. The one-time enrollment code is never stored here —
// it is consumed exactly once by the enroll flow.
type AgentConfig struct {
	ServerURL string `json:"server_url"`
	HostID    int    `json:"host_id"`
	Token     string `json:"token"`
}

func Load(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

func Save(path string, cfg *AgentConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	// 0600: 이 파일에 host-bound 토큰이 들어있으므로 소유자만 읽을 수 있게 제한
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
