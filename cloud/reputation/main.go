// Servicio de reputación en la nube del NGAV (MVP).
//
// Expone la reputación de ficheros por su hash SHA-256. Es un servicio de
// lectura masiva y baja latencia: en producción estaría respaldado por un
// almacén clave-valor distribuido (ScyllaDB/DynamoDB) con caché de edge/CDN;
// aquí se usa un mapa en memoria sembrado desde un fichero de datos.
//
// Endpoints:
//
//	GET  /v1/reputation/{sha256}     -> { "hash", "verdict", "prevalence", "first_seen" }
//	POST /v1/reputation/report       -> registra una observación (con control de influencia)
//	GET  /healthz                    -> healthcheck
//	GET  /metrics                    -> métricas básicas en texto
//
// Uso solo de la librería estándar para compilar sin dependencias externas.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Verdict de reputación devuelto al agente.
type Verdict string

const (
	VerdictGood    Verdict = "good"
	VerdictBad     Verdict = "bad"
	VerdictUnknown Verdict = "unknown"
)

// Record es la reputación almacenada de un hash.
type Record struct {
	Verdict    Verdict `json:"verdict"`
	Prevalence int64   `json:"prevalence"`
	FirstSeen  int64   `json:"first_seen"`
}

// Store es un almacén de reputación seguro para concurrencia.
type Store struct {
	mu   sync.RWMutex
	data map[string]*Record
}

func NewStore() *Store {
	return &Store{data: make(map[string]*Record)}
}

func (s *Store) Lookup(hash string) Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, ok := s.data[strings.ToLower(hash)]; ok {
		return *r
	}
	return Record{Verdict: VerdictUnknown}
}

// Set siembra o sobrescribe la reputación de un hash (uso administrativo).
func (s *Store) Set(hash string, r Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[strings.ToLower(hash)] = &r
}

// Report registra una observación desde el campo.
//
// DEFENSA ANTI-ENVENENAMIENTO: una observación del campo NUNCA cambia por sí
// sola un veredicto a "good". Solo incrementa la prevalencia. La promoción a
// "good"/"bad" ocurre fuera de banda (pipeline validado en la nube). Esto
// impide que un atacante "enseñe" al sistema que su malware es benigno
// simplemente reportándolo muchas veces.
func (s *Store) Report(hash string) Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := strings.ToLower(hash)
	r, ok := s.data[h]
	if !ok {
		r = &Record{Verdict: VerdictUnknown, FirstSeen: time.Now().Unix()}
		s.data[h] = r
	}
	r.Prevalence++
	return *r
}

// Métricas de servicio.
var (
	lookupCount atomic.Int64
	reportCount atomic.Int64
)

const hashLen = 64

func isHex(s string) bool {
	if len(s) != hashLen {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// Server agrupa los handlers HTTP.
type Server struct {
	store *Store
}

func (srv *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	hash := strings.TrimPrefix(r.URL.Path, "/v1/reputation/")
	if !isHex(hash) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hash sha256 inválido"})
		return
	}
	lookupCount.Add(1)
	rec := srv.store.Lookup(hash)
	writeJSON(w, http.StatusOK, map[string]any{
		"hash":       strings.ToLower(hash),
		"verdict":    rec.Verdict,
		"prevalence": rec.Prevalence,
		"first_seen": rec.FirstSeen,
	})
}

func (srv *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "usa POST"})
		return
	}
	var body struct {
		Hash string `json:"hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !isHex(body.Hash) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cuerpo inválido"})
		return
	}
	reportCount.Add(1)
	rec := srv.store.Report(body.Hash)
	writeJSON(w, http.StatusOK, map[string]any{
		"hash":       strings.ToLower(body.Hash),
		"verdict":    rec.Verdict,
		"prevalence": rec.Prevalence,
		"note":       "observación registrada; el veredicto solo cambia vía pipeline validado",
	})
}

// latestSignatures es la base de firmas que sirve el canal de actualización.
// En producción sería un artefacto FIRMADO distribuido vía TUF/CDN.
const latestSignatures = `# Base de firmas NGAV servida por el canal de actualización
sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR-Test-File
pattern 4549434152 EICAR-Pattern
pattern 6d696d696b617a7a Trojan.Mimikatz
pattern 786d726967 Miner.XMRig
pattern 73656b75726c7361 Trojan.CredDump
pattern 2f6465762f7463702f Backdoor.ReverseShell
pattern 76737361646d696e Ransomware.ShadowDelete
`

func (srv *Server) handleSignatures(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(latestSignatures))
}

func (srv *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/reputation/report", srv.handleReport)
	mux.HandleFunc("/v1/reputation/", srv.handleLookup)
	mux.HandleFunc("/v1/signatures", srv.handleSignatures)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(
			"ngav_reputation_lookups_total " + itoa(lookupCount.Load()) + "\n" +
				"ngav_reputation_reports_total " + itoa(reportCount.Load()) + "\n"))
	})
	return mux
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// seed carga datos de reputación iniciales (denylist/allowlist conocidos).
func seed(store *Store) {
	// EICAR (fichero de prueba estándar) marcado como malo.
	store.Set("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", Record{
		Verdict: VerdictBad, Prevalence: 1_000_000, FirstSeen: 0,
	})
	// SHA-256 de fichero vacío: benigno y ultra-prevalente (allowlist).
	store.Set("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Record{
		Verdict: VerdictGood, Prevalence: 999_999_999, FirstSeen: 0,
	})
}

func main() {
	addr := os.Getenv("NGAV_REP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	store := NewStore()
	seed(store)
	srv := &Server{store: store}

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("servicio de reputación NGAV escuchando en %s", addr)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("servidor detenido: %v", err)
	}
}
