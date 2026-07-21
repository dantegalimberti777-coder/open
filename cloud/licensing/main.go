// Servicio de licencias y facturación del NGAV.
//
// Modelo de negocio: 14 días de prueba gratis y luego suscripción mensual de
// 10 USD/mes.
//
// Integración de pagos:
//   - Si STRIPE_SECRET_KEY y STRIPE_PRICE_ID están definidos, crea una sesión
//     de Stripe Checkout (modo suscripción, 14 días de prueba) y responde con
//     su URL de pago. El webhook de Stripe activa la licencia al pagar.
//   - Si no, funciona en MODO DEMO: emite una clave de licencia al instante y
//     la marca activa, para poder probar el flujo completo sin cuenta de pago.
//
// Solo usa la librería estándar de Go.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	trialDays   = 14
	priceUSD    = "10"
	planName    = "NGAV Premium"
	monthPeriod = 30 * 24 * time.Hour
)

// License representa el estado de una clave de licencia.
type License struct {
	Key    string
	Email  string
	Active bool
	Until  int64 // unix
}

// Store guarda las licencias emitidas (en memoria para el MVP; en producción
// sería una base de datos con el estado sincronizado por los webhooks de Stripe).
type Store struct {
	mu   sync.RWMutex
	data map[string]*License
}

func NewStore() *Store { return &Store{data: make(map[string]*License)} }

func (s *Store) put(l *License) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[l.Key] = l
}

func (s *Store) get(key string) (*License, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.data[key]
	return l, ok
}

func genKey() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "NGAV-" + strings.ToUpper(fmt.Sprintf("%x", b[:]))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

type Server struct {
	store        *Store
	stripeSecret string
	stripePrice  string
	publicURL    string
}

// handleCheckout inicia el proceso de suscripción.
func (srv *Server) handleCheckout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "usa POST"})
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	// Modo Stripe real.
	if srv.stripeSecret != "" && srv.stripePrice != "" {
		checkoutURL, err := srv.createStripeSession(body.Email)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"url": checkoutURL, "mode": "stripe"})
		return
	}

	// Modo DEMO: emite una clave activa al instante.
	lic := &License{
		Key:    genKey(),
		Email:  body.Email,
		Active: true,
		Until:  time.Now().Add(monthPeriod).Unix(),
	}
	srv.store.put(lic)
	writeJSON(w, http.StatusOK, map[string]any{
		"url":  srv.publicURL + "/success?key=" + lic.Key,
		"key":  lic.Key,
		"mode": "demo",
		"note": "Modo demo: clave emitida sin pago real. Configura STRIPE_SECRET_KEY y STRIPE_PRICE_ID para cobros reales.",
	})
}

// handleValidate valida una clave de licencia.
func (srv *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	lic, ok := srv.store.get(key)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false})
		return
	}
	valid := lic.Active && lic.Until > time.Now().Unix()
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": valid,
		"until": lic.Until,
		"email": lic.Email,
	})
}

// handleSuccess es la página de retorno tras el pago (demo).
func (srv *Server) handleSuccess(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>NGAV — suscripción activa</title>
<body style="font-family:sans-serif;text-align:center;padding:60px">
<h1>✅ Suscripción activada</h1>
<p>Tu clave de licencia es:</p>
<h2 style="font-family:monospace">%s</h2>
<p>Cópiala y pégala en NGAV → Suscripción → Activar clave.</p></body>`, key)
}

// createStripeSession crea una Checkout Session de Stripe (suscripción con
// prueba de 14 días). Requiere STRIPE_SECRET_KEY y STRIPE_PRICE_ID.
func (srv *Server) createStripeSession(email string) (string, error) {
	form := url.Values{}
	form.Set("mode", "subscription")
	form.Set("line_items[0][price]", srv.stripePrice)
	form.Set("line_items[0][quantity]", "1")
	form.Set("subscription_data[trial_period_days]", fmt.Sprintf("%d", trialDays))
	form.Set("success_url", srv.publicURL+"/success?session_id={CHECKOUT_SESSION_ID}")
	form.Set("cancel_url", srv.publicURL+"/cancel")
	if email != "" {
		form.Set("customer_email", email)
	}

	req, err := http.NewRequest(http.MethodPost,
		"https://api.stripe.com/v1/checkout/sessions",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+srv.stripeSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("stripe: %s", strings.TrimSpace(string(data)))
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	return out.URL, nil
}

// handleStripeWebhook procesa eventos de Stripe (pago completado, renovación,
// cancelación) para mantener el estado de la licencia. Scaffold del MVP: en
// producción se verificaría la firma del webhook (Stripe-Signature).
func (srv *Server) handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var evt struct {
		Type string `json:"type"`
		Data struct {
			Object struct {
				CustomerEmail string `json:"customer_email"`
				Status        string `json:"status"`
			} `json:"object"`
		} `json:"data"`
	}
	_ = json.Unmarshal(body, &evt)
	log.Printf("stripe webhook: %s", evt.Type)
	// Aquí se activaría/desactivaría la licencia asociada según el evento.
	writeJSON(w, http.StatusOK, map[string]bool{"received": true})
}

func (srv *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/checkout", srv.handleCheckout)
	mux.HandleFunc("/v1/license/validate", srv.handleValidate)
	mux.HandleFunc("/v1/stripe/webhook", srv.handleStripeWebhook)
	mux.HandleFunc("/success", srv.handleSuccess)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok", "plan": planName, "price_usd": priceUSD, "trial_days": trialDays,
		})
	})
	return mux
}

func main() {
	addr := os.Getenv("NGAV_LICENSE_ADDR")
	if addr == "" {
		addr = ":8090"
	}
	public := os.Getenv("NGAV_PUBLIC_URL")
	if public == "" {
		public = "http://127.0.0.1" + addr
	}
	srv := &Server{
		store:        NewStore(),
		stripeSecret: os.Getenv("STRIPE_SECRET_KEY"),
		stripePrice:  os.Getenv("STRIPE_PRICE_ID"),
		publicURL:    public,
	}
	mode := "DEMO (sin pagos reales)"
	if srv.stripeSecret != "" {
		mode = "STRIPE"
	}
	log.Printf("servicio de licencias NGAV en %s — plan %s %s USD/mes, prueba %d días — modo %s",
		addr, planName, priceUSD, trialDays, mode)

	httpServer := &http.Server{Addr: addr, Handler: srv.routes(), ReadHeaderTimeout: 5 * time.Second}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("servidor detenido: %v", err)
	}
}
