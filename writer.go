package audit

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type writer struct {
	service   string
	queue     chan record
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	accepting atomic.Bool
	senders   atomic.Int64
	dropped   atomic.Uint64
	ctx       context.Context
	cancel    context.CancelFunc
	insert    func(context.Context, string, []any) error
}

// startWriter is also the test seam; callers serialize lifecycle changes.
func startWriter(service string, insert func(context.Context, string, []any) error, flushEvery, reportEvery time.Duration) *writer {
	ctx, cancel := context.WithCancel(context.Background())
	w := &writer{
		service: service, queue: make(chan record, 2048), stop: make(chan struct{}),
		done: make(chan struct{}), ctx: ctx, cancel: cancel, insert: insert,
	}
	w.accepting.Store(true)
	lastWriter = w
	current.Store(w)
	go w.run(flushEvery, reportEvery)
	return w
}

func (w *writer) offer(r record) {
	w.senders.Add(1)
	defer w.senders.Add(-1)
	if !w.accepting.Load() {
		return
	}
	select {
	case w.queue <- r:
	default:
		w.dropped.Add(1)
	}
}

func (w *writer) run(flushEvery, reportEvery time.Duration) {
	defer close(w.done)
	defer w.cancel()
	flushTick, reportTick := time.NewTicker(flushEvery), time.NewTicker(reportEvery)
	defer flushTick.Stop()
	defer reportTick.Stop()
	pending := make([]record, 0, 500)
	add := func(r record) {
		r.prepare()
		pending = append(pending, r)
		if len(pending) == 500 {
			w.flush(pending)
			clear(pending)
			pending = pending[:0]
		}
	}
	for {
		select {
		case r := <-w.queue:
			add(r)
		case <-flushTick.C:
			w.flush(pending)
			clear(pending)
			pending = pending[:0]
		case <-reportTick.C:
			if count := w.dropped.Swap(0); count != 0 {
				log.Printf("audit: dropped %d records", count)
			}
		case <-w.stop:
			// A sender that observed accepting=true must finish before the last drain.
			for w.senders.Load() != 0 {
				runtime.Gosched()
			}
			for {
				select {
				case r := <-w.queue:
					add(r)
				default:
					w.flush(pending)
					return
				}
			}
		}
	}
}

func (w *writer) flush(pending []record) {
	groups := make(map[string][]any)
	for _, r := range pending {
		groups[r.Domain] = append(groups[r.Domain], r)
	}
	for domain, docs := range groups {
		ctx, cancel := context.WithTimeout(w.ctx, 5*time.Second)
		err := func() (err error) {
			defer func() {
				if p := recover(); p != nil {
					err = fmt.Errorf("insert panic: %v", p)
				}
			}()
			return w.insert(ctx, domain, docs)
		}()
		cancel()
		if err != nil {
			w.dropped.Add(uint64(len(docs)))
			log.Printf("audit: insert failed for %s (%d records): %v", domain, len(docs), err)
		}
	}
}

func mongoInsert(client *mongo.Client) func(context.Context, string, []any) error {
	seen := make(map[string]bool)
	return func(ctx context.Context, domain string, docs []any) error {
		collection := client.Database(strings.ReplaceAll(domain, ".", "_")).Collection("audit_logs")
		if !seen[domain] {
			seen[domain] = true
			_, err := collection.Indexes().CreateMany(ctx, []mongo.IndexModel{
				{Keys: bson.D{{Key: "at", Value: -1}}, Options: options.Index().SetName("audit_by_time")},
				{Keys: bson.D{{Key: "actor_id", Value: 1}, {Key: "at", Value: -1}}, Options: options.Index().SetName("audit_by_actor")},
				{Keys: bson.D{{Key: "kind", Value: 1}, {Key: "at", Value: -1}}, Options: options.Index().SetName("audit_by_kind")},
				{Keys: bson.D{{Key: "at", Value: 1}}, Options: options.Index().SetName("audit_ttl").SetExpireAfterSeconds(365 * 24 * 60 * 60).SetPartialFilterExpression(bson.D{{Key: "kind", Value: "request"}})},
			})
			if err != nil {
				log.Printf("audit: index creation failed for %s: %v", domain, err)
			}
		}
		_, err := collection.InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
		return err
	}
}
