package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientAddsBearerToken(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewEncoder(w).Encode(map[string]string{"ok": "true"}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer ts.Close()

	var out map[string]string
	if err := NewClient(ts.URL, "tok").getJSON("/api/sessions", &out); err != nil {
		t.Fatalf("getJSON failed: %v", err)
	}

	if gotAuth != "Bearer tok" {
		t.Fatalf("Authorization = %q, want %q", gotAuth, "Bearer tok")
	}
}

func TestJoinArgsQuotesSpaces(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		want    string
	}{
		{name: "arg spaces", command: "shell", args: []string{"whoami /all", "x"}, want: `shell "whoami /all" x`},
		{name: "command spaces", command: "run program", args: nil, want: `"run program"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := joinCommandArgs(tt.command, tt.args); got != tt.want {
				t.Fatalf("joinCommandArgs = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestQuoteArgEscapesQuotesAndEmpty(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{name: "empty", arg: "", want: `""`},
		{name: "raw", arg: "whoami", want: "whoami"},
		{name: "quote", arg: `say "hi"`, want: `"say \"hi\""`},
		{name: "trailing slash", arg: `C:\Program Files\`, want: `"C:\Program Files\\"`},
		{name: "slash before quote", arg: `C:\Tools\"quoted"`, want: `"C:\Tools\\\"quoted\""`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := quoteArg(tt.arg); got != tt.want {
				t.Fatalf("quoteArg(%q) = %q, want %q", tt.arg, got, tt.want)
			}
		})
	}
}

func TestResultRouteAddsSinceOnlyWhenPositive(t *testing.T) {
	tests := []struct {
		name     string
		beaconID uint32
		since    int64
		want     string
	}{
		{name: "no since", beaconID: 7, since: 0, want: "/api/results/7"},
		{name: "with since", beaconID: 7, since: 42, want: "/api/results/7?since=42"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resultRoute(tt.beaconID, tt.since); got != tt.want {
				t.Fatalf("resultRoute(%d, %d) = %q, want %q", tt.beaconID, tt.since, got, tt.want)
			}
		})
	}
}
