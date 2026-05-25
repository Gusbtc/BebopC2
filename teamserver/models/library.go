package models

import "time"

type LibraryEntry struct {
	Name        string    `json:"name"`
	File        string    `json:"file,omitempty"`
	Kind        string    `json:"kind"`
	Source      string    `json:"source"`
	Description string    `json:"description,omitempty"`
	Usage       string    `json:"usage,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Deletable   bool      `json:"deletable"`
	Size        int64     `json:"size"`
	UpdatedAt   time.Time `json:"updated_at"`
}
