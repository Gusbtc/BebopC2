package models

import "time"

type Result struct {
	Label      uint32
	BeaconID   uint32
	Flags      uint16
	Type       uint8
	Filename   string
	Output     string
	ReceivedAt time.Time
}
