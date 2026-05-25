package version

import "testing"

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		remote  string
		current string
		want    bool
	}{
		{"1.4.1", "1.5.0", false},
		{"1.5.0", "1.5.0", false},
		{"1.5.1", "1.5.0", true},
		{"2.0.0", "1.9.9", true},
		{"1.10.0", "1.9.9", true},
	}

	for _, tt := range tests {
		if got := isNewerVersion(tt.remote, tt.current); got != tt.want {
			t.Fatalf("isNewerVersion(%q, %q) = %v, want %v", tt.remote, tt.current, got, tt.want)
		}
	}
}
