package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer() *Server {
	store := NewStore()
	seed(store)
	return &Server{store: store}
}

func TestLookupKnownBad(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/reputation/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", nil)
	w := httptest.NewRecorder()
	srv.handleLookup(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["verdict"] != "bad" {
		t.Errorf("verdict = %v, want bad", body["verdict"])
	}
}

func TestLookupKnownGood(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/reputation/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", nil)
	w := httptest.NewRecorder()
	srv.handleLookup(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["verdict"] != "good" {
		t.Errorf("verdict = %v, want good", body["verdict"])
	}
}

func TestLookupUnknown(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/reputation/"+strings.Repeat("a", 64), nil)
	w := httptest.NewRecorder()
	srv.handleLookup(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["verdict"] != "unknown" {
		t.Errorf("verdict = %v, want unknown", body["verdict"])
	}
}

func TestInvalidHashRejected(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/v1/reputation/not-a-hash", nil)
	w := httptest.NewRecorder()
	srv.handleLookup(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code = %d, want 400", w.Code)
	}
}

// Verifica la defensa anti-envenenamiento: reportar un hash desconocido muchas
// veces NO lo convierte en "good"; solo incrementa la prevalencia.
func TestReportDoesNotPoisonVerdict(t *testing.T) {
	srv := newTestServer()
	hash := strings.Repeat("b", 64)
	for i := 0; i < 1000; i++ {
		body := strings.NewReader(`{"hash":"` + hash + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/reputation/report", body)
		w := httptest.NewRecorder()
		srv.handleReport(w, req)
	}
	rec := srv.store.Lookup(hash)
	if rec.Verdict != VerdictUnknown {
		t.Errorf("verdict = %v, want unknown (no debe promoverse por reportes)", rec.Verdict)
	}
	if rec.Prevalence != 1000 {
		t.Errorf("prevalence = %d, want 1000", rec.Prevalence)
	}
}

func TestReportRejectsGet(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/v1/reputation/report", nil)
	w := httptest.NewRecorder()
	srv.handleReport(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("code = %d, want 405", w.Code)
	}
}

func TestIsHex(t *testing.T) {
	if !isHex(strings.Repeat("aF0", 21) + "a") { // 64 chars
		t.Error("valid hex rejected")
	}
	if isHex("xyz") {
		t.Error("short invalid hex accepted")
	}
}
