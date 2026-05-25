package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func withProxyOrigin(t *testing.T, raw string) {
	t.Helper()
	origin, err := parseProxyOrigin(raw)
	if err != nil {
		t.Fatalf("parseProxyOrigin: %v", err)
	}
	old := proxyTargetOrigin
	proxyTargetOrigin = origin
	t.Cleanup(func() { proxyTargetOrigin = old })
}

func TestProxyTeamserverRequiresBearer(t *testing.T) {
	withProxyOrigin(t, "http://127.0.0.1:8080")
	req := httptest.NewRequest(http.MethodGet, "/api/proxy?url=http://127.0.0.1:8080/api/sessions", nil)
	w := httptest.NewRecorder()

	proxyTeamserver(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestProxyTeamserverRejectsNonAPITarget(t *testing.T) {
	withProxyOrigin(t, "http://127.0.0.1:8080")
	req := httptest.NewRequest(http.MethodGet, "/api/proxy?url=http://127.0.0.1:8080/admin", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()

	proxyTeamserver(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestProxyTeamserverRejectsNonAllowlistedHost(t *testing.T) {
	withProxyOrigin(t, "http://127.0.0.1:8080")
	req := httptest.NewRequest(http.MethodGet, "/api/proxy?url=http://example.com/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()

	proxyTeamserver(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestProxyTeamserverDoesNotFollowRedirects(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/redirect" {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		t.Fatalf("unexpected path = %q", r.URL.Path)
	}))
	defer upstream.Close()
	withProxyOrigin(t, upstream.URL)

	target := url.QueryEscape(upstream.URL + "/api/redirect")
	req := httptest.NewRequest(http.MethodGet, "/api/proxy?url="+target, nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()

	proxyTeamserver(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
}

func TestProxyTeamserverForwardsAPITarget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/sessions" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()
	withProxyOrigin(t, upstream.URL)

	target := url.QueryEscape(upstream.URL + "/api/sessions")
	req := httptest.NewRequest(http.MethodGet, "/api/proxy?url="+target, nil)
	req.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()

	proxyTeamserver(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %q", w.Code, w.Body.String())
	}
	if w.Body.String() != `{"ok":true}` {
		t.Fatalf("body = %q", w.Body.String())
	}
}
