package models

import "time"

type ImplantMetadata struct {
	ID          uint32
	ListenerID  uint32 // ID of the listener that received the registration
	SessionKey  []byte
	Sleep       uint32
	Jitter      uint32
	Username    string
	Hostname    string
	ProcessName string
	ProcessID   uint32
	Arch        uint8  // 0=x86, 1=x64
	Platform    uint8  // 2=windows
	Integrity   uint8  // 2=medium, 3=high, 4=system
}

type Beacon struct {
	ImplantMetadata
	FirstSeen time.Time
	LastSeen  time.Time
}

func (b *Beacon) IsAlive() bool {
	s := b.Sleep
	if s == 0 {
		s = 60 // default if Sleep not yet configured
	}
	return time.Since(b.LastSeen) < time.Duration(s*3)*time.Second
}
