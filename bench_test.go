package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Matching through a real router happens once so these benchmarks isolate the
// middleware's cost from mux's own context allocations.
func benchmarkRequest(method string) *http.Request {
	var matched *http.Request
	router := testRouter(Options{}, "benchmark", func(w http.ResponseWriter, r *http.Request) { matched = r })
	router.ServeHTTP(httptest.NewRecorder(), request(method, validClaims, ""))
	return matched
}

func BenchmarkUnrecorded(b *testing.B) {
	r := benchmarkRequest("GET")
	testWriter(b, time.Hour, func(context.Context, string, []any) error { return nil })
	handler := Middleware(Options{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(w, r)
	}
}

func BenchmarkRecorded(b *testing.B) {
	r := benchmarkRequest("POST")
	testWriter(b, time.Hour, func(context.Context, string, []any) error { return nil })
	handler := Middleware(Options{})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	w := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(w, r)
	}
}
