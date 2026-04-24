package models

import "time"

// ChatMessage is a single entry in the operator chat channel.
// Operator is always set from the JWT subject on the server, never
// from client payload.
type ChatMessage struct {
	ID        int64     `json:"id"`
	Operator  string    `json:"operator"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}
