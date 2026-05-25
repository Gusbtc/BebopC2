package models

import (
	"testing"
	"time"
)

func TestBeaconIsAliveAtUsesSleepPlusGrace(t *testing.T) {
	now := time.Unix(1700000000, 0)
	b := &Beacon{
		ImplantMetadata: ImplantMetadata{Sleep: 5},
		LastSeen:        now.Add(-14 * time.Second),
	}
	if !b.IsAliveAt(now) {
		t.Fatal("beacon should be alive before sleep+10 threshold")
	}

	b.LastSeen = now.Add(-15 * time.Second)
	if b.IsAliveAt(now) {
		t.Fatal("beacon should be dead at sleep+10 threshold")
	}
}
