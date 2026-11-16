package main

import (
	"net/url"
	"testing"
	"time"
)

func TestSession(t *testing.T) {
	s := &server{key: []byte("k")}
	good := s.sign(time.Now().Add(time.Minute))
	if !s.valid(good) {
		t.Fatal("fresh session rejected")
	}
	for name, token := range map[string]string{
		"expired":   s.sign(time.Now().Add(-time.Minute)),
		"tampered":  "9" + good,
		"other key": (&server{key: []byte("x")}).sign(time.Now().Add(time.Minute)),
		"empty":     "",
	} {
		if s.valid(token) {
			t.Errorf("%s session accepted", name)
		}
	}
}

func TestLogFilter(t *testing.T) {
	q := url.Values{"kind": {"config"}, "failed": {"1"}, "q": {"a.b"}, "from": {"2026-11-16T00:00:00Z"},
		"before": {"1700000000000_0123456789abcdef01234567"}, "service": {"auth"}}
	filter, err := logFilter(q.Get)
	if err != nil || len(filter) != 6 {
		t.Fatalf("filter = %v, err = %v", filter, err)
	}
	for _, bad := range []url.Values{{"from": {"yesterday"}}, {"before": {"1_zz"}}} {
		if _, err := logFilter(bad.Get); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if f, _ := logFilter(url.Values{"kind": {"$ne"}}.Get); len(f) != 0 {
		t.Errorf("unknown kind reached the filter: %v", f)
	}
}

func TestSignInLimit(t *testing.T) {
	s, now := &server{}, time.Now()
	for i := 0; i < maxFailures; i++ {
		if !s.allow(false, now) {
			t.Fatalf("attempt %d refused early", i)
		}
	}
	if s.allow(true, now) {
		t.Fatal("correct password accepted while locked")
	}
	if !s.allow(true, now.Add(61*time.Second)) {
		t.Fatal("still locked after the window")
	}
}
