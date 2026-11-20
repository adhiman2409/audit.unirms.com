package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

const validClaims = `{"Authorised":true,"Tenant":"actor-1","Domain":"example.com","Department":"ops","Name":"Ada","EmailId":"ada@example.com","PhoneNumber":"123","Role":"admin","OrgName":"Example"}`

type recordSink struct {
	mu      sync.Mutex
	records []record
	domains []string
}

func (s *recordSink) insert(_ context.Context, domain string, docs []any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domains = append(s.domains, domain)
	for _, doc := range docs {
		s.records = append(s.records, doc.(record))
	}
	return nil
}

func (s *recordSink) snapshot() []record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]record(nil), s.records...)
}

func testWriter(t testing.TB, interval time.Duration, insert func(context.Context, string, []any) error) *writer {
	t.Helper()
	lifecycleMu.Lock()
	w := startWriter("test-service", insert, interval, time.Hour)
	lifecycleMu.Unlock()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		Close(ctx)
		select {
		case <-w.done:
		default:
			t.Error("writer did not stop")
		}
	})
	return w
}

func testRouter(opts Options, name string, handler http.HandlerFunc) *mux.Router {
	router := mux.NewRouter()
	router.Use(Middleware(opts))
	router.HandleFunc("/items/{id}", handler).Name(name)
	return router
}

func request(method, claims, body string) *http.Request {
	r := httptest.NewRequest(method, "/items/42", strings.NewReader(body))
	if claims != "" {
		r = r.WithContext(context.WithValue(r.Context(), "claims", claims))
	}
	return r
}

func waitFor[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for writer")
		var zero T
		return zero
	}
}

func TestClassification(t *testing.T) {
	tests := []struct {
		name, method, claims string
		opts                 Options
		want                 int
	}{
		{"post", "POST", validClaims, Options{}, 1},
		{"get", "GET", validClaims, Options{}, 0},
		{"head", "HEAD", validClaims, Options{}, 0},
		{"options", "OPTIONS", validClaims, Options{}, 0},
		{"also", "GET", validClaims, Options{AlsoRecord: []string{"route"}}, 1},
		{"skip", "POST", validClaims, Options{Skip: []string{"route"}}, 0},
		{"capture-get", "GET", validClaims, Options{CaptureBody: []string{"route"}}, 1},
		{"capture-overrides-skip", "POST", validClaims, Options{CaptureBody: []string{"route"}, Skip: []string{"route"}}, 1},
		{"also-overrides-skip", "POST", validClaims, Options{AlsoRecord: []string{"route"}, Skip: []string{"route"}}, 1},
		{"no-claims", "POST", "", Options{}, 0},
		{"empty-domain", "POST", `{"Tenant":"actor-1"}`, Options{}, 0},
		{"invalid-claims", "POST", `{`, Options{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &recordSink{}
			testWriter(t, time.Hour, sink.insert)
			called := false
			router := testRouter(tt.opts, "route", func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			})
			router.ServeHTTP(httptest.NewRecorder(), request(tt.method, tt.claims, ""))
			Close(context.Background())
			if !called || len(sink.snapshot()) != tt.want {
				t.Fatalf("handler called=%v, records=%d, want %d", called, len(sink.snapshot()), tt.want)
			}
		})
	}
}

func TestRecordContents(t *testing.T) {
	sink := &recordSink{}
	testWriter(t, time.Hour, sink.insert)
	router := testRouter(Options{}, "update-item", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Correlation-ID", "correlation-123")
		time.Sleep(2 * time.Millisecond)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, `{"message":"invalid item"}`)
	})
	r := request("PATCH", validClaims, "")
	r.Header.Add("X-Forwarded-For", "10.0.0.9")
	r.Header.Add("X-Forwarded-For", " 203.0.113.1, 198.51.100.7 ")
	before := time.Now()
	router.ServeHTTP(httptest.NewRecorder(), r)
	after := time.Now()
	Close(context.Background())
	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("records=%d", len(got))
	}
	rec := got[0]
	if rec.Status != 422 || rec.Route != "update-item" || rec.Method != "PATCH" || rec.Path != "/items/42" || rec.PathVars["id"] != "42" || rec.Service != "test-service" {
		t.Fatalf("wrong request fields: %+v", rec)
	}
	if rec.ActorID != "actor-1" || rec.ActorName != "Ada" || rec.ActorEmail != "ada@example.com" || rec.ActorRole != "admin" || rec.Department != "ops" || rec.Domain != "example.com" {
		t.Fatalf("wrong actor fields: %+v", rec)
	}
	if rec.Kind != "request" || rec.CorrelationID != "correlation-123" || rec.Error != "invalid item" || rec.IP != "198.51.100.7" {
		t.Fatalf("wrong response fields: %+v", rec)
	}
	if rec.At.Location() != time.UTC || rec.At.Before(before) || rec.At.After(after) || rec.DurationMS < 2 || rec.rawBody != nil || rec.rawError != nil {
		t.Fatalf("wrong timing or raw data retained: %+v", rec)
	}
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

func TestBodyCapture(t *testing.T) {
	tests := []struct {
		name, contentType, body string
		want                    any
		truncated               bool
	}{
		{"redacted", "application/json; charset=utf-8", `{"outer":{"PassWord":"p","items":[{"TOKEN":"t","secret":{"a":1},"Otp":123,"keep":true}]}}`, map[string]any{"outer": map[string]any{"PassWord": "[redacted]", "items": []any{map[string]any{"TOKEN": "[redacted]", "secret": "[redacted]", "Otp": "[redacted]", "keep": true}}}}, false},
		{"redacted-variants", "application/json", `{"smtp_password":"p","api-key":"k","clientSecret":"s","access.token":"t","otp_code":1,"userOtp":2,"Credentials":{"a":1},"key":"field","footprint":3,"notPublic":true}`, map[string]any{"smtp_password": "[redacted]", "api-key": "[redacted]", "clientSecret": "[redacted]", "access.token": "[redacted]", "otp_code": "[redacted]", "userOtp": "[redacted]", "Credentials": "[redacted]", "key": "field", "footprint": float64(3), "notPublic": true}, false},
		{"limit", "application/json", `"` + strings.Repeat("x", 8190) + `"`, strings.Repeat("x", 8190), false},
		{"overflow", "application/json", `"` + strings.Repeat("x", 10000) + `"`, nil, true},
		{"one-byte-over", "application/json", `"` + strings.Repeat("x", 8191) + `"`, nil, true},
		{"non-json", "text/plain", `{"password":"p"}`, nil, false},
		{"invalid-json", "application/json", `{`, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &recordSink{}
			testWriter(t, time.Hour, sink.insert)
			body := &trackedBody{Reader: strings.NewReader(tt.body)}
			router := testRouter(Options{CaptureBody: []string{"config"}}, "config", func(w http.ResponseWriter, r *http.Request) {
				read, err := io.ReadAll(r.Body)
				if err != nil || string(read) != tt.body {
					t.Errorf("handler body changed: err=%v", err)
				}
				_ = r.Body.Close()
			})
			r := request("PUT", validClaims, "")
			r.Body = body
			r.Header.Set("Content-Type", tt.contentType)
			router.ServeHTTP(httptest.NewRecorder(), r)
			Close(context.Background())
			got := sink.snapshot()
			if len(got) != 1 {
				t.Fatalf("records=%d", len(got))
			}
			rec := got[0]
			if !body.closed || rec.Kind != "config" || rec.BodyTruncated != tt.truncated || !reflect.DeepEqual(rec.Body, tt.want) {
				t.Fatalf("closed=%v kind=%s truncated=%v body matches=%v", body.closed, rec.Kind, rec.BodyTruncated, reflect.DeepEqual(rec.Body, tt.want))
			}
		})
	}
}

func TestFullChannelDoesNotBlock(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	w := testWriter(t, time.Hour, func(context.Context, string, []any) error {
		once.Do(func() { close(entered); <-release })
		return nil
	})
	defer close(release)
	router := testRouter(Options{}, "update", func(http.ResponseWriter, *http.Request) {})
	for i := 0; i < 500; i++ {
		router.ServeHTTP(httptest.NewRecorder(), request("POST", validClaims, ""))
	}
	waitFor(t, entered)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for i := 0; i < cap(w.queue)+10; i++ {
			router.ServeHTTP(httptest.NewRecorder(), request("POST", validClaims, ""))
		}
	}()
	waitFor(t, finished)
	if w.dropped.Load() != 10 || len(w.queue) != cap(w.queue) {
		t.Fatalf("dropped=%d queued=%d", w.dropped.Load(), len(w.queue))
	}
}

func TestFailedInsertKeepsRunning(t *testing.T) {
	batches := make(chan int, 2)
	calls := 0
	w := testWriter(t, time.Hour, func(_ context.Context, _ string, docs []any) error {
		calls++
		batches <- len(docs)
		if calls == 1 {
			return errors.New("database unavailable")
		}
		return nil
	})
	for batch := 0; batch < 2; batch++ {
		for i := 0; i < 500; i++ {
			w.offer(record{Domain: "example.com"})
		}
		if size := waitFor(t, batches); size != 500 {
			t.Fatalf("batch size=%d", size)
		}
	}
	Close(context.Background())
	if calls != 2 || w.dropped.Load() != 500 {
		t.Fatalf("calls=%d dropped=%d", calls, w.dropped.Load())
	}
}

func TestDisabled(t *testing.T) {
	Close(context.Background())
	t.Setenv("AUDIT_DISABLED", "true")
	Start(nil, "disabled")
	called := false
	w := httptest.NewRecorder()
	router := testRouter(Options{}, "disabled", func(got http.ResponseWriter, r *http.Request) {
		called = true
		if got != w {
			t.Error("disabled middleware wrapped the response writer")
		}
	})
	router.ServeHTTP(w, request("POST", validClaims, ""))
	if !called || current.Load() != nil {
		t.Fatal("disabled middleware did not pass through")
	}
}

func TestShutdown(t *testing.T) {
	t.Run("drain-and-idempotence", func(t *testing.T) {
		sink := &recordSink{}
		w := testWriter(t, time.Hour, sink.insert)
		for _, domain := range []string{"one.example", "two.example", "one.example"} {
			w.offer(record{Domain: domain})
		}
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); Close(context.Background()) }()
		}
		wg.Wait()
		if len(sink.snapshot()) != 3 || len(sink.domains) != 2 || current.Load() != nil {
			t.Fatalf("records=%d batches=%d", len(sink.snapshot()), len(sink.domains))
		}
		w.offer(record{Domain: "closed.example"})
		if len(w.queue) != 0 {
			t.Fatal("closed writer accepted a record")
		}
	})
	t.Run("signal-flushes-before-reraise", func(t *testing.T) {
		sink := &recordSink{}
		w := testWriter(t, time.Hour, sink.insert)
		w.offer(record{Domain: "example.com"})
		original := reRaise
		defer func() { reRaise = original }()
		called := false
		reRaise = func(sig os.Signal) {
			called = true
			if sig != syscall.SIGTERM || len(sink.snapshot()) != 1 || current.Load() != nil {
				t.Error("signal was re-raised before flush or with the wrong signal")
			}
		}
		handleSignal(syscall.SIGTERM)
		if !called {
			t.Fatal("signal was not re-raised")
		}
	})
	t.Run("deadline-with-blocked-insert", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		w := testWriter(t, time.Millisecond, func(ctx context.Context, _ string, _ []any) error {
			close(entered)
			<-release // Deliberately ignores cancellation.
			return ctx.Err()
		})
		defer close(release)
		w.offer(record{Domain: "example.com"})
		waitFor(t, entered)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		returned := make(chan struct{})
		go func() { Close(ctx); close(returned) }()
		waitFor(t, returned)
		if ctx.Err() == nil || w.ctx.Err() == nil || current.Load() != nil {
			t.Fatal("Close did not honor its deadline and cancel the writer")
		}
	})
}

func TestFlushBySize(t *testing.T) {
	batches := make(chan int, 1)
	w := testWriter(t, 2*time.Second, func(ctx context.Context, _ string, docs []any) error {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 5*time.Second {
			t.Error("insert is missing its five second deadline")
		}
		batches <- len(docs)
		return nil
	})
	for i := 0; i < 500; i++ {
		w.offer(record{Domain: "example.com"})
	}
	if size := waitFor(t, batches); size != 500 {
		t.Fatalf("batch size=%d", size)
	}
}

type panicClaimsContext struct{ context.Context }

func (c panicClaimsContext) Value(key any) any {
	if key == "claims" {
		panic("claims context panic")
	}
	return c.Context.Value(key)
}

func TestPanicBoundaries(t *testing.T) {
	sink := &recordSink{}
	testWriter(t, time.Hour, sink.insert)
	called := false
	router := testRouter(Options{}, "panic", func(w http.ResponseWriter, r *http.Request) { called = true })
	r := request("POST", "", "")
	r = r.WithContext(panicClaimsContext{r.Context()})
	router.ServeHTTP(httptest.NewRecorder(), r)
	if !called {
		t.Fatal("audit panic prevented handler execution")
	}
	router = testRouter(Options{}, "panic", func(w http.ResponseWriter, r *http.Request) {
		r.URL = nil // Triggers a panic in record building after the handler returns.
	})
	router.ServeHTTP(httptest.NewRecorder(), request("POST", validClaims, ""))
	router = testRouter(Options{}, "panic", func(http.ResponseWriter, *http.Request) { panic("handler panic") })
	func() {
		defer func() {
			if p := recover(); p != "handler panic" {
				t.Errorf("handler panic was swallowed: %v", p)
			}
		}()
		router.ServeHTTP(httptest.NewRecorder(), request("POST", validClaims, ""))
	}()
	Close(context.Background())
	if len(sink.snapshot()) != 0 {
		t.Fatal("panicking audit or handler produced a record")
	}
}

func TestStatusAndErrorCapture(t *testing.T) {
	tests := []struct {
		name   string
		write  func(http.ResponseWriter)
		status int
		err    string
	}{
		{"default", func(http.ResponseWriter) {}, 200, ""},
		{"first-status", func(w http.ResponseWriter) { w.WriteHeader(409); w.WriteHeader(500) }, 409, ""},
		{"first-write-only", func(w http.ResponseWriter) {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"message":"first"}`)
			_, _ = io.WriteString(w, `{"message":"second"}`)
		}, 400, "first"},
		{"error-limit", func(w http.ResponseWriter) {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"message":"`+strings.Repeat("é", 301)+`"}`)
		}, 400, strings.Repeat("é", 300)},
		{"capture-limit", func(w http.ResponseWriter) {
			w.WriteHeader(400)
			_, _ = io.WriteString(w, `{"message":"`+strings.Repeat("x", 1024)+`"}`)
		}, 400, ""},
		{"flush", func(w http.ResponseWriter) { w.(http.Flusher).Flush() }, 200, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := &recordSink{}
			testWriter(t, time.Hour, sink.insert)
			response := httptest.NewRecorder()
			router := testRouter(Options{}, "status", func(w http.ResponseWriter, r *http.Request) {
				if w.(interface{ Unwrap() http.ResponseWriter }).Unwrap() != response {
					t.Error("Unwrap returned the wrong writer")
				}
				tt.write(w)
			})
			router.ServeHTTP(response, request("POST", validClaims, ""))
			Close(context.Background())
			got := sink.snapshot()[0]
			if got.Status != tt.status || got.Error != tt.err || got.IP != "192.0.2.1" {
				t.Fatalf("status=%d error=%q ip=%q", got.Status, got.Error, got.IP)
			}
			if tt.name == "flush" && !response.Flushed {
				t.Fatal("Flush was not forwarded")
			}
		})
	}
}

func TestMiddlewareLifecycleAndAllocations(t *testing.T) {
	Close(context.Background())
	var matched *http.Request
	router := testRouter(Options{}, "read", func(w http.ResponseWriter, r *http.Request) { matched = r })
	router.ServeHTTP(httptest.NewRecorder(), request("GET", validClaims, ""))
	response := httptest.NewRecorder()
	var called atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		if w != response {
			t.Error("pass-through wrapped writer")
		}
	})
	wrapped := Middleware(Options{})(handler) // Constructed before writer starts.
	wrapped.ServeHTTP(response, matched)
	sink := &recordSink{}
	testWriter(t, time.Hour, sink.insert)
	bareAllocs := testing.AllocsPerRun(100, func() { handler.ServeHTTP(response, matched) })
	auditAllocs := testing.AllocsPerRun(100, func() { wrapped.ServeHTTP(response, matched) })
	if auditAllocs != bareAllocs || auditAllocs != 0 {
		t.Fatalf("bare allocations=%v, audit allocations=%v", bareAllocs, auditAllocs)
	}
	post := Middleware(Options{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	post.ServeHTTP(response, request("POST", validClaims, "")) // Also checks a nil mux route.
	Close(context.Background())
	wrapped.ServeHTTP(response, matched)
	if called.Load() == 0 || len(sink.snapshot()) != 1 || sink.snapshot()[0].Route != "" {
		t.Fatal("middleware lifecycle or unnamed route failed")
	}
}

func TestTargetIDs(t *testing.T) {
	var body any
	if err := json.Unmarshal([]byte(`{"employee_id":"E1","employeeIds":["E2","E1"," "],"rows":[{"eid":"E3","manager_eid":"M1"}],"emp_id":7,"meta":{"Emp_Id":"E4"}}`), &body); err != nil {
		t.Fatal(err)
	}
	if got, want := targetIDs(map[string]string{"eid": "E0", "id": "X"}, body), []string{"E0", "E1", "E2", "E3", "E4"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("targets=%v, want %v", got, want)
	}
	if got := targetIDs(nil, nil); got != nil {
		t.Fatalf("no input gave %v", got)
	}
}

func TestRequestRecordsTargetsWithoutBody(t *testing.T) {
	sink := &recordSink{}
	testWriter(t, time.Hour, sink.insert)
	router := testRouter(Options{}, "update", func(w http.ResponseWriter, r *http.Request) {
		if read, _ := io.ReadAll(r.Body); string(read) != `{"employee_id":"E9","note":"x"}` {
			t.Errorf("handler body changed: %s", read)
		}
	})
	r := request("POST", validClaims, `{"employee_id":"E9","note":"x"}`)
	r.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(httptest.NewRecorder(), r)
	Close(context.Background())
	got := sink.snapshot()
	if len(got) != 1 || got[0].Kind != "request" || got[0].Body != nil || !reflect.DeepEqual(got[0].TargetIDs, []string{"E9"}) {
		t.Fatalf("record=%+v", got)
	}
}
