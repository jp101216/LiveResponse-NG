package collector

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

// defaultGrace is how long a collector gets, after its deadline, to hand back
// partial results before the dispatcher stops waiting for it.
const defaultGrace = 2 * time.Second

// Dispatcher runs a set of collectors concurrently with a bounded worker
// pool. Parallelism is the main speed win over the sequential PowerShell
// predecessor: on a live host most collection time is spent waiting on the
// OS (handle enumeration, registry reads), so overlapping it pays off.
type Dispatcher struct {
	Workers int           // max collectors running at once
	Timeout time.Duration // per-collector budget; 0 means no limit
	// Grace is how long to wait after the timeout for a collector that honours
	// cancellation to return its partial results. 0 means defaultGrace.
	Grace time.Duration
}

// Run executes every collector and returns one Result per collector, in the
// same order as cs, so reports are stable and diffable across runs and hosts.
//
// A panicking or hanging collector is contained. A panic becomes an error
// result. A collector that ignores cancellation (blocked in a syscall or a
// DNS lookup, say) is abandoned once its timeout plus grace period expires, so
// the run always finishes and the report always gets written.
func (d *Dispatcher) Run(ctx context.Context, cs []Collector) []Result {
	out := make([]Result, len(cs))
	if len(cs) == 0 {
		return out
	}
	workers := d.Workers
	if workers < 1 {
		workers = 4
	}
	if workers > len(cs) {
		workers = len(cs)
	}

	idx := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				// Each worker writes only its own slot. Once the run is
				// cancelled (Ctrl+C), collectors not yet started are recorded
				// as not run instead of being started against a dead context.
				if err := ctx.Err(); err != nil {
					out[i] = finalize(Result{Errors: []string{
						"not run: the run was interrupted before this collector started (" + err.Error() + ")"}},
						cs[i].Name(), time.Now().UTC())
					continue
				}
				out[i] = d.runOne(ctx, cs[i])
			}
		}()
	}
	for i := range cs {
		idx <- i
	}
	close(idx)
	wg.Wait()
	return out
}

// TimeoutOverride lets a collector that legitimately runs long (memory
// scanning) set its own budget instead of the dispatcher-wide one.
type TimeoutOverride interface {
	Timeout() time.Duration
}

type outcome struct {
	res      Result
	err      error
	panicked bool
	panicMsg string
}

// runOne executes a single collector in its own goroutine under its own
// timeout. Running it in a separate goroutine is what makes the timeout real:
// the dispatcher can stop waiting even when the collector cannot be stopped.
func (d *Dispatcher) runOne(ctx context.Context, c Collector) Result {
	name := c.Name()
	start := time.Now().UTC()

	timeout := d.Timeout
	if t, ok := c.(TimeoutOverride); ok && t.Timeout() > 0 {
		timeout = t.Timeout()
	}

	var (
		cctx   context.Context
		cancel context.CancelFunc
	)
	if timeout > 0 {
		cctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		cctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	// Buffered so an abandoned collector can still finish later without
	// blocking forever on a send nobody will receive.
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "lrng: collector %q panicked: %v\n%s\n", name, r, debug.Stack())
				done <- outcome{panicked: true, panicMsg: fmt.Sprint(r)}
			}
		}()
		res, err := c.Collect(cctx)
		done <- outcome{res: res, err: err}
	}()

	var o outcome
	select {
	case o = <-done:
	case <-cctx.Done():
		grace := d.Grace
		if grace <= 0 {
			grace = defaultGrace
		}
		select {
		case o = <-done: // collector honoured cancellation: keep its partial results
		case <-time.After(grace):
			return finalize(Result{Errors: []string{fmt.Sprintf(
				"collector did not stop within %s of cancellation (%v); abandoned, no results",
				grace, cctx.Err())}}, name, start)
		}
	}

	res := o.res
	if o.panicked {
		res = Result{Errors: []string{"panic: " + o.panicMsg}}
	}
	if o.err != nil {
		res.Fail(o.err.Error())
	}
	return finalize(res, name, start)
}

// finalize guarantees the invariants every Result in a report should have,
// whatever state the collector left it in.
func finalize(r Result, name string, start time.Time) Result {
	r.Collector = name
	if r.StartedAt.IsZero() {
		r.StartedAt = start
	}
	if r.Duration == 0 {
		r.Duration = time.Since(r.StartedAt)
	}
	if r.Records == nil {
		r.Records = []Record{} // "records": [] rather than null for parsers
	}
	return r
}
