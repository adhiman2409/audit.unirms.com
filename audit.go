// Package audit asynchronously records data-changing mux requests in MongoDB.
package audit

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
)

type Options struct {
	AlsoRecord  []string // Names of GET routes that change data.
	Skip        []string // Names of non-GET routes that only read.
	CaptureBody []string // Names of configuration routes whose JSON body is stored.
}

var (
	current     atomic.Pointer[writer]
	lifecycleMu sync.Mutex
	startOnce   sync.Once
	lastWriter  *writer
	// reRaise sends sig again after the audit channel has stopped listening.
	// If the service has its own handler, that handler gets it and its graceful
	// shutdown runs; otherwise the default action ends the process.
	reRaise = func(sig os.Signal) {
		if s, ok := sig.(syscall.Signal); ok {
			_ = syscall.Kill(syscall.Getpid(), s)
		}
	}
)

// Start starts the writer and shutdown listener once for this process.
func Start(client *mongo.Client, service string) {
	if os.Getenv("AUDIT_DISABLED") == "true" {
		return
	}
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	startOnce.Do(func() {
		w := startWriter(service, mongoInsert(client), 2*time.Second, time.Minute)
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			defer signal.Stop(signals)
			select {
			case sig := <-signals:
				signal.Stop(signals)
				handleSignal(sig)
			case <-w.stop:
			}
		}()
	})
}

// Close stops accepting records and waits for the final flush, bounded by ctx.
func Close(ctx context.Context) {
	lifecycleMu.Lock()
	w := lastWriter
	current.Store(nil)
	if w != nil {
		w.closeOnce.Do(func() {
			w.accepting.Store(false)
			close(w.stop)
		})
	}
	lifecycleMu.Unlock()
	if w == nil {
		return
	}
	select {
	case <-w.done:
	case <-ctx.Done():
		w.cancel()
	}
}

func handleSignal(sig os.Signal) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	Close(ctx)
	reRaise(sig)
}
