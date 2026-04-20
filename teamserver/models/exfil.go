package models

import "time"

type ExfilEntry struct {
	Label    uint32    `json:"label"`
	Filename string    `json:"filename"`
	BeaconID uint32    `json:"beacon_id"`
	Size     int64     `json:"size"`
	ExfilAt  time.Time `json:"exfil_at"`
}
