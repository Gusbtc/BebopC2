package models

import "time"

type Result struct {
	Label         uint32
	BeaconID      uint32
	Flags         uint16
	Type          uint8
	Filename      string
	Output        string
	ExitCode      int32
	Stdout        string
	Stderr        string
	Exception     string
	DurationMS    uint32
	Truncated     bool
	Mode          string
	BridgeVersion string
	Diagnostics   string
	ReceivedAt    time.Time
}
