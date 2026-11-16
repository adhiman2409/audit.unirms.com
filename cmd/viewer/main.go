// Command viewer serves a read-only web page over the audit_logs collections
// that the audit middleware writes, behind a single username and password.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

//go:embed index.html
var page []byte

const (
	cookieName = "audit_session"
	sessionTTL = 12 * time.Hour
	pageSize   = 100
)

var dbName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)

type server struct {
	client     *mongo.Client
	user, pass [sha256.Size]byte
	key        []byte
	loginLock  sync.Mutex
}

func main() {
	user, pass := os.Getenv("AUDIT_UI_USER"), os.Getenv("AUDIT_UI_PASSWORD")
	if user == "" || len(pass) < 12 {
		log.Fatal("viewer: set AUDIT_UI_USER and an AUDIT_UI_PASSWORD of at least 12 characters")
	}
	// Same variables the services use to reach MongoDB.
	opts := options.Client().ApplyURI(os.Getenv("DB_ADDR") + os.Getenv("DB_PORT"))
	if u := os.Getenv("DB_USER"); u != "" {
		opts.SetAuth(options.Credential{Username: u, Password: os.Getenv("DB_PASSWORD")})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	client, err := mongo.Connect(ctx, opts)
	if err == nil {
		err = client.Ping(ctx, nil)
	}
	cancel()
	if err != nil {
		log.Fatalf("viewer: mongo: %v", err)
	}
	// A fresh key per start: restarting the viewer signs everyone out.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	s := &server{client: client, user: sha256.Sum256([]byte(user)), pass: sha256.Sum256([]byte(pass)), key: key}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Printf("viewer: listening on :%s", port)
	log.Fatal((&http.Server{Addr: ":" + port, Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'")
		w.Write(page)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /api/tenants", s.auth(s.tenants))
	mux.HandleFunc("GET /api/services", s.auth(s.services))
	mux.HandleFunc("GET /api/logs", s.auth(s.logs))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, r)
	})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	user, pass := sha256.Sum256([]byte(r.FormValue("username"))), sha256.Sum256([]byte(r.FormValue("password")))
	ok := subtle.ConstantTimeCompare(user[:], s.user[:]) & subtle.ConstantTimeCompare(pass[:], s.pass[:])
	if ok != 1 {
		// ponytail: one global lock means at most one wrong guess per second
		// for everybody. Move to per-IP limits if that ever locks out real users.
		s.loginLock.Lock()
		time.Sleep(time.Second)
		s.loginLock.Unlock()
		log.Printf("viewer: failed sign-in from %s", clientIP(r))
		http.Error(w, "wrong username or password", http.StatusUnauthorized)
		return
	}
	log.Printf("viewer: sign-in from %s", clientIP(r))
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: s.sign(time.Now().Add(sessionTTL)), Path: "/",
		MaxAge: int(sessionTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func clientIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		return f
	}
	return r.RemoteAddr
}

// sign returns "<unix expiry>.<hmac of the expiry>".
func (s *server) sign(expires time.Time) string {
	exp := strconv.FormatInt(expires.Unix(), 10)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(exp))
	return exp + "." + hex.EncodeToString(mac.Sum(nil))
}

func (s *server) valid(token string) bool {
	exp, _, _ := strings.Cut(token, ".")
	unix, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().Unix() > unix {
		return false
	}
	return hmac.Equal([]byte(token), []byte(s.sign(time.Unix(unix, 0))))
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || !s.valid(c.Value) {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func reply(w http.ResponseWriter, v any, err error) {
	if err != nil {
		log.Printf("viewer: %v", err)
		http.Error(w, "could not read the audit log", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// tenants lists the databases that hold an audit_logs collection.
func (s *server) tenants(w http.ResponseWriter, r *http.Request) {
	names, err := s.client.ListDatabaseNames(r.Context(), bson.D{})
	found := []string{}
	for _, name := range names {
		if err != nil {
			break
		}
		var has []string
		has, err = s.client.Database(name).ListCollectionNames(r.Context(), bson.D{{Key: "name", Value: "audit_logs"}})
		if len(has) != 0 {
			found = append(found, name)
		}
	}
	reply(w, found, err)
}

func (s *server) collection(w http.ResponseWriter, r *http.Request) *mongo.Collection {
	db := r.URL.Query().Get("db")
	if !dbName.MatchString(db) {
		http.Error(w, "unknown tenant", http.StatusBadRequest)
		return nil
	}
	return s.client.Database(db).Collection("audit_logs")
}

func (s *server) services(w http.ResponseWriter, r *http.Request) {
	if c := s.collection(w, r); c != nil {
		names, err := c.Distinct(r.Context(), "service", bson.D{})
		reply(w, names, err)
	}
}

func (s *server) logs(w http.ResponseWriter, r *http.Request) {
	c := s.collection(w, r)
	if c == nil {
		return
	}
	filter, err := logFilter(r.URL.Query().Get)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	cursor, err := c.Find(ctx, filter, options.Find().
		SetSort(bson.D{{Key: "at", Value: -1}, {Key: "_id", Value: -1}}).SetLimit(pageSize+1))
	rows := []bson.M{}
	if err == nil {
		err = cursor.All(ctx, &rows)
	}
	out := struct {
		Rows []bson.M
		Next string
	}{Rows: rows}
	if len(rows) > pageSize {
		out.Rows = rows[:pageSize]
		last := out.Rows[pageSize-1]
		at, _ := last["at"].(primitive.DateTime)
		id, _ := last["_id"].(primitive.ObjectID)
		out.Next = strconv.FormatInt(int64(at), 10) + "_" + id.Hex()
	}
	reply(w, out, err)
}

type badQuery string

func (b badQuery) Error() string { return string(b) }

// logFilter turns the query string into a Mongo filter. get is url.Values.Get.
func logFilter(get func(string) string) (bson.D, error) {
	filter := bson.D{}
	if kind := get("kind"); kind == "config" || kind == "request" {
		filter = append(filter, bson.E{Key: "kind", Value: kind})
	}
	if service := get("service"); service != "" {
		filter = append(filter, bson.E{Key: "service", Value: service})
	}
	if get("failed") != "" {
		filter = append(filter, bson.E{Key: "status", Value: bson.D{{Key: "$gte", Value: 400}}})
	}
	at := bson.D{}
	for param, op := range map[string]string{"from": "$gte", "to": "$lt"} {
		if v := get(param); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return nil, badQuery(param + " is not a valid time")
			}
			at = append(at, bson.E{Key: op, Value: t})
		}
	}
	if len(at) != 0 {
		filter = append(filter, bson.E{Key: "at", Value: at})
	}
	if q := strings.TrimSpace(get("q")); q != "" {
		// ponytail: unanchored regex scans the tenant's (90-day) collection.
		// Add a text index if a tenant's log grows past a few million rows.
		match := primitive.Regex{Pattern: regexp.QuoteMeta(q), Options: "i"}
		or := bson.A{}
		for _, field := range []string{"actor_name", "actor_email", "actor_id", "route", "path", "ip", "correlation_id"} {
			or = append(or, bson.D{{Key: field, Value: match}})
		}
		filter = append(filter, bson.E{Key: "$or", Value: or})
	}
	if before := get("before"); before != "" {
		ms, hexID, _ := strings.Cut(before, "_")
		millis, err1 := strconv.ParseInt(ms, 10, 64)
		id, err2 := primitive.ObjectIDFromHex(hexID)
		if err1 != nil || err2 != nil {
			return nil, badQuery("before is not a valid cursor")
		}
		t := primitive.DateTime(millis)
		filter = append(filter, bson.E{Key: "$and", Value: bson.A{bson.D{{Key: "$or", Value: bson.A{
			bson.D{{Key: "at", Value: bson.D{{Key: "$lt", Value: t}}}},
			bson.D{{Key: "at", Value: t}, {Key: "_id", Value: bson.D{{Key: "$lt", Value: id}}}},
		}}}}})
	}
	return filter, nil
}
