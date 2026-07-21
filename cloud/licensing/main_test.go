package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer() *Server {
	return &Server{store: NewStore(), publicURL: "http://127.0.0.1:8090"}
}

func TestCheckoutDemoIssuesActiveKey(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/v1/checkout",
		strings.NewReader(`{"email":"user@example.com"}`))
	w := httptest.NewRecorder()
	srv.handleCheckout(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	key, _ := body["key"].(string)
	if !strings.HasPrefix(key, "NGAV-") {
		t.Fatalf("key = %q, want NGAV- prefix", key)
	}
	if body["mode"] != "demo" {
		t.Errorf("mode = %v, want demo", body["mode"])
	}
}

func TestValidateIssuedKey(t *testing.T) {
	srv := newTestServer()
	// Emite una clave vía checkout.
	req := httptest.NewRequest(http.MethodPost, "/v1/checkout", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	srv.handleCheckout(w, req)
	var issued map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &issued)
	key := issued["key"].(string)

	// Valídala.
	vreq := httptest.NewRequest(http.MethodGet, "/v1/license/validate?key="+key, nil)
	vw := httptest.NewRecorder()
	srv.handleValidate(vw, vreq)
	var v map[string]any
	_ = json.Unmarshal(vw.Body.Bytes(), &v)
	if v["valid"] != true {
		t.Errorf("valid = %v, want true", v["valid"])
	}
}

func TestValidateUnknownKeyIsInvalid(t *testing.T) {
	srv := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/v1/license/validate?key=NGAV-UNKNOWN", nil)
	w := httptest.NewRecorder()
	srv.handleValidate(w, req)
	var v map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	if v["valid"] != false {
		t.Errorf("valid = %v, want false", v["valid"])
	}
}

func TestKeysAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		k := genKey()
		if seen[k] {
			t.Fatalf("clave duplicada: %s", k)
		}
		seen[k] = true
	}
}
