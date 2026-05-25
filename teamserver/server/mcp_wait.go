package server

import (
	"encoding/json"
	"fmt"
	"time"
)

type mcpTaskWaitArgs struct {
	BeaconID  uint32 `json:"beacon_id"`
	Label     uint32 `json:"label"`
	TimeoutMS int    `json:"timeout_ms"`
}

func (s *mcpHTTPServer) waitForResult(beaconID uint32, label uint32, timeout time.Duration) (any, error) {
	deadline := time.Now().Add(timeout)
	for {
		result, found, err := s.findResult(beaconID, label)
		if err != nil {
			return nil, err
		}
		if found {
			return result, nil
		}
		now := time.Now()
		if !now.Before(deadline) {
			return nil, fmt.Errorf("timeout waiting for task result")
		}
		sleepFor := 250 * time.Millisecond
		if remaining := time.Until(deadline); remaining < sleepFor {
			sleepFor = remaining
		}
		time.Sleep(sleepFor)
	}
}

func (s *mcpHTTPServer) findResult(beaconID uint32, label uint32) (any, bool, error) {
	var out []map[string]any
	if err := s.client.getJSON(mcpResultRoute(beaconID, 0), &out); err != nil {
		return nil, false, err
	}
	for _, item := range out {
		if mcpNumericID(item["label"]) == label {
			return item, true, nil
		}
	}
	return nil, false, nil
}

func decodeMCPTaskWaitArgs(raw json.RawMessage) (mcpTaskWaitArgs, error) {
	var req mcpTaskWaitArgs
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, err
	}
	if req.BeaconID == 0 || req.Label == 0 {
		return req, fmt.Errorf("beacon_id and label required")
	}
	if req.TimeoutMS == 0 {
		req.TimeoutMS = 60000
	}
	if req.TimeoutMS < 1 || req.TimeoutMS > 300000 {
		return req, fmt.Errorf("timeout_ms must be 1-300000")
	}
	return req, nil
}

func mcpTimeoutFromArgs(raw json.RawMessage, fallbackMS int) time.Duration {
	var tmp struct {
		TimeoutMS int `json:"timeout_ms"`
	}
	_ = json.Unmarshal(raw, &tmp)
	if tmp.TimeoutMS <= 0 {
		tmp.TimeoutMS = fallbackMS
	}
	if tmp.TimeoutMS > 300000 {
		tmp.TimeoutMS = 300000
	}
	return time.Duration(tmp.TimeoutMS) * time.Millisecond
}

func mcpRequireConfirm(raw json.RawMessage) error {
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return err
	}
	if !req.Confirm {
		return fmt.Errorf("confirm=true required")
	}
	return nil
}
