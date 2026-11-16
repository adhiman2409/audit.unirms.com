package audit

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Middleware records matching requests whenever a writer is running.
func Middleware(opts Options) mux.MiddlewareFunc {
	also, skip, capture := make(map[string]bool), make(map[string]bool), make(map[string]bool)
	for _, name := range opts.AlsoRecord {
		also[name] = true
	}
	for _, name := range opts.Skip {
		skip[name] = true
	}
	for _, name := range opts.CaptureBody {
		capture[name] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writer := current.Load()
			if writer == nil {
				next.ServeHTTP(w, r)
				return
			}
			name := ""
			if route := mux.CurrentRoute(r); route != nil {
				name = route.GetName()
			}
			readOnly := r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions
			if !also[name] && !capture[name] && (readOnly || skip[name]) {
				next.ServeHTTP(w, r)
				return
			}
			state := prepareRequest(w, r, capture[name])
			if state == nil {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(state.response, r)
			state.finish(writer, r, name)
		})
	}
}

type requestState struct {
	claims struct {
		Authorised  bool
		Tenant      string
		Domain      string
		Department  string
		Name        string
		EmailId     string
		PhoneNumber string
		Role        string
		OrgName     string
	}
	response *statusWriter
	body     *bodyReader
	config   bool
	started  time.Time
}

func auditPanic() {
	if p := recover(); p != nil {
		log.Printf("audit: recovered panic: %v", p)
	}
}

func prepareRequest(w http.ResponseWriter, r *http.Request, config bool) (state *requestState) {
	defer auditPanic()
	claims, ok := r.Context().Value("claims").(string)
	if !ok {
		return nil
	}
	s := &requestState{config: config}
	if json.Unmarshal([]byte(claims), &s.claims) != nil || s.claims.Domain == "" {
		return nil
	}
	s.response = &statusWriter{ResponseWriter: w, status: http.StatusOK}
	if config && strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") && r.Body != nil {
		s.body = &bodyReader{ReadCloser: r.Body}
		r.Body = s.body
	}
	s.started = time.Now()
	return s
}

func (s *requestState) finish(w *writer, r *http.Request, name string) {
	defer auditPanic()
	returned := time.Now()
	kind := "request"
	if s.config {
		kind = "config"
	}
	forwarded, _, _ := strings.Cut(r.Header.Get("X-Forwarded-For"), ",")
	ip := strings.TrimSpace(forwarded)
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	var vars map[string]string
	if original := mux.Vars(r); len(original) > 0 {
		vars = make(map[string]string, len(original))
		for key, value := range original {
			vars[key] = value
		}
	}
	rec := record{
		At: returned.UTC(), Kind: kind, Service: w.service, Route: name,
		Method: r.Method, Path: r.URL.Path, PathVars: vars, Status: s.response.status,
		DurationMS: returned.Sub(s.started).Milliseconds(), Domain: s.claims.Domain,
		ActorID: s.claims.Tenant, ActorName: s.claims.Name, ActorEmail: s.claims.EmailId,
		ActorRole: s.claims.Role, Department: s.claims.Department,
		CorrelationID: s.response.Header().Get("X-Correlation-ID"), IP: ip,
		rawError: s.response.firstWrite,
	}
	if s.body != nil {
		rec.BodyTruncated = len(s.body.copied) > 8192
		rec.rawBody = s.body.copied
	}
	w.offer(rec)
}

type statusWriter struct {
	http.ResponseWriter
	status     int
	wrote      bool
	sawWrite   bool
	firstWrite []byte
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *statusWriter) WriteHeader(status int) {
	if w.wrote {
		return
	}
	if status >= 200 || status == http.StatusSwitchingProtocols {
		w.status, w.wrote = status, true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	func() {
		defer auditPanic()
		if !w.sawWrite && w.status >= 400 {
			n := len(p)
			if n > 1024 {
				n = 1024
			}
			w.firstWrite = append(w.firstWrite, p[:n]...)
		}
		w.sawWrite = true
	}()
	return w.ResponseWriter.Write(p)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if !w.wrote {
			w.WriteHeader(http.StatusOK)
		}
		f.Flush()
	}
}

type bodyReader struct {
	io.ReadCloser
	copied []byte
}

func (b *bodyReader) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	func() {
		defer auditPanic()
		keep := n
		if remaining := 8193 - len(b.copied); keep > remaining {
			keep = remaining
		}
		b.copied = append(b.copied, p[:keep]...)
	}()
	return n, err
}
