package models

import "time"

const (
	TaskStatusPending   = "PENDING"
	TaskStatusSent      = "SENT"
	TaskStatusCompleted = "COMPLETED"
)

type Task struct {
	Label      uint32
	BeaconID   uint32
	Type       uint8
	Code       uint8
	Flags      uint16
	Identifier uint32
	Data       []byte
	Status     string
	CreatedAt  time.Time
}
