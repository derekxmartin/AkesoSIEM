package correlate

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

// StateManager coordinates expiration and memory bounds across all
// correlation evaluators. It runs a background goroutine that
// periodically evicts expired state and enforces per-rule bucket limits.
//
// Thread-safe: all methods are safe for concurrent use.
type StateManager struct {
	eventCount *EventCountEvaluator
	valueCount *ValueCountEvaluator
	temporal   *TemporalEvaluator

	expiryInterval time.Duration
	maxBuckets     int // max buckets/chains per rule (0 = unlimited)

	totalExpired atomic.Int64

	cancel context.CancelFunc
	done   chan struct{}
}

// StateManagerConfig holds settings for the state manager.
type StateManagerConfig struct {
	// ExpiryInterval is how often the expiration goroutine runs.
	ExpiryInterval time.Duration

	// MaxBucketsPerRule is the maximum number of group-by buckets (or
	// temporal chains) per correlation rule. 0 means unlimited.
	MaxBucketsPerRule int
}

// DefaultStateManagerConfig returns sensible defaults.
func DefaultStateManagerConfig() StateManagerConfig {
	return StateManagerConfig{
		ExpiryInterval:    30 * time.Second,
		MaxBucketsPerRule: 10000,
	}
}

// NewStateManager creates a state manager for the given evaluators.
// Any evaluator may be nil if that correlation type is not in use.
func NewStateManager(
	ec *EventCountEvaluator,
	vc *ValueCountEvaluator,
	tp *TemporalEvaluator,
	cfg StateManagerConfig,
) *StateManager {
	if cfg.ExpiryInterval <= 0 {
		cfg.ExpiryInterval = 30 * time.Second
	}

	return &StateManager{
		eventCount:     ec,
		valueCount:     vc,
		temporal:       tp,
		expiryInterval: cfg.ExpiryInterval,
		maxBuckets:     cfg.MaxBucketsPerRule,
		done:           make(chan struct{}),
	}
}

// Start launches the background expiration goroutine.
func (sm *StateManager) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	sm.cancel = cancel

	go sm.runLoop(ctx)
	log.Printf("Correlation state manager started (expiry every %s, max %d buckets/rule)",
		sm.expiryInterval, sm.maxBuckets)
}

// Stop cancels the background goroutine and waits for it to exit.
func (sm *StateManager) Stop() {
	if sm.cancel != nil {
		sm.cancel()
	}
	<-sm.done
	log.Println("Correlation state manager stopped")
}

// runLoop is the background expiration goroutine.
func (sm *StateManager) runLoop(ctx context.Context) {
	defer close(sm.done)

	ticker := time.NewTicker(sm.expiryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			expired := sm.expireAll()
			pruned := sm.pruneAll()
			if expired > 0 || pruned > 0 {
				log.Printf("State manager: expired %d buckets, pruned %d over-limit", expired, pruned)
			}
		}
	}
}

// expireAll calls ExpireState on each evaluator and returns the total expired.
func (sm *StateManager) expireAll() int {
	now := time.Now()
	total := 0

	if sm.eventCount != nil {
		total += sm.eventCount.ExpireState(now)
	}
	if sm.valueCount != nil {
		total += sm.valueCount.ExpireState(now)
	}
	if sm.temporal != nil {
		total += sm.temporal.ExpireState(now)
	}

	sm.totalExpired.Add(int64(total))
	return total
}

// pruneAll enforces max bucket limits on each evaluator.
func (sm *StateManager) pruneAll() int {
	if sm.maxBuckets <= 0 {
		return 0
	}

	total := 0

	if sm.eventCount != nil {
		total += sm.eventCount.PruneToLimit(sm.maxBuckets)
	}
	if sm.valueCount != nil {
		total += sm.valueCount.PruneToLimit(sm.maxBuckets)
	}
	if sm.temporal != nil {
		total += sm.temporal.PruneToLimit(sm.maxBuckets)
	}

	return total
}

// HealthHandler returns an HTTP handler that serves correlation state
// health as JSON. Mounted at GET /api/v1/correlate/health.
func (sm *StateManager) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		health := sm.Health()

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(health); err != nil {
			http.Error(w, "failed to encode health", http.StatusInternalServerError)
		}
	}
}

// CorrelationHealth is the JSON structure for the health endpoint.
type CorrelationHealth struct {
	EventCount   map[string]int `json:"event_count"`
	ValueCount   map[string]int `json:"value_count"`
	Temporal     map[string]int `json:"temporal"`
	TotalExpired int64          `json:"total_expired"`
	MaxBuckets   int            `json:"max_buckets_per_rule"`
}

// Health returns the current correlation state health snapshot.
func (sm *StateManager) Health() CorrelationHealth {
	h := CorrelationHealth{
		EventCount:   make(map[string]int),
		ValueCount:   make(map[string]int),
		Temporal:     make(map[string]int),
		TotalExpired: sm.totalExpired.Load(),
		MaxBuckets:   sm.maxBuckets,
	}

	if sm.eventCount != nil {
		h.EventCount = sm.eventCount.Stats()
	}
	if sm.valueCount != nil {
		h.ValueCount = sm.valueCount.Stats()
	}
	if sm.temporal != nil {
		h.Temporal = sm.temporal.Stats()
	}

	return h
}

// --- PruneToLimit methods on each evaluator ---

// PruneToLimit removes the oldest buckets from each rule until the
// bucket count is at or below the limit. Returns the number pruned.
func (e *EventCountEvaluator) PruneToLimit(limit int) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	pruned := 0
	for _, entry := range e.rules {
		for len(entry.buckets) > limit {
			// Find and remove the bucket with the oldest newest-timestamp.
			oldestKey := ""
			var oldestTime time.Time
			for key, bucket := range entry.buckets {
				newest := newestTimestamp(bucket.timestamps)
				if oldestKey == "" || newest.Before(oldestTime) {
					oldestKey = key
					oldestTime = newest
				}
			}
			if oldestKey != "" {
				delete(entry.buckets, oldestKey)
				pruned++
			}
		}
	}
	return pruned
}

// PruneToLimit removes the oldest buckets from each rule until the
// bucket count is at or below the limit. Returns the number pruned.
func (e *ValueCountEvaluator) PruneToLimit(limit int) int {
	e.mu.Lock()
	defer e.mu.Unlock()

	pruned := 0
	for _, entry := range e.rules {
		for len(entry.buckets) > limit {
			oldestKey := ""
			var oldestTime time.Time
			for key, bucket := range entry.buckets {
				newest := newestValueTimestamp(bucket.entries)
				if oldestKey == "" || newest.Before(oldestTime) {
					oldestKey = key
					oldestTime = newest
				}
			}
			if oldestKey != "" {
				delete(entry.buckets, oldestKey)
				pruned++
			}
		}
	}
	return pruned
}

// PruneToLimit removes the oldest chains from each rule until the
// chain count is at or below the limit. Returns the number pruned.
func (te *TemporalEvaluator) PruneToLimit(limit int) int {
	te.mu.Lock()
	defer te.mu.Unlock()

	pruned := 0
	for _, entry := range te.rules {
		for len(entry.chains) > limit {
			oldestKey := ""
			var oldestStart time.Time
			for key, chain := range entry.chains {
				if oldestKey == "" || chain.startTime.Before(oldestStart) {
					oldestKey = key
					oldestStart = chain.startTime
				}
			}
			if oldestKey != "" {
				delete(entry.chains, oldestKey)
				pruned++
			}
		}
	}
	return pruned
}

// newestTimestamp returns the newest (last) timestamp in the slice.
func newestTimestamp(timestamps []time.Time) time.Time {
	if len(timestamps) == 0 {
		return time.Time{}
	}
	return timestamps[len(timestamps)-1]
}

// newestValueTimestamp returns the newest timestamp from value entries.
func newestValueTimestamp(entries []valueEntry) time.Time {
	if len(entries) == 0 {
		return time.Time{}
	}
	return entries[len(entries)-1].timestamp
}

// --- Mutex-free methods for testing ---

// TotalExpired returns the cumulative count of expired buckets/chains.
func (sm *StateManager) TotalExpired() int64 {
	return sm.totalExpired.Load()
}

// ExpireOnce runs a single expiration cycle (for testing without
// starting the background goroutine).
func (sm *StateManager) ExpireOnce() int {
	expired := sm.expireAll()
	pruned := sm.pruneAll()
	return expired + pruned
}

