package watch

import (
	"context"
	"errors"
	"io"
	"runtime"
	"sync/atomic"
	"time"
)

// ErrUnsupported is returned by Record where no live source exists yet.
var ErrUnsupported = errors.New("watch mode records on Windows and Linux; -watch-from replays a saved stream on any OS")

// RecordOptions configure a live recording.
type RecordOptions struct {
	Duration time.Duration
	RunID    string // names the ETW session lrng-watch-<run id>
	Host     string
	SelfPID  uint32
	Limits   Limits
	// Raw, when set, receives the normalized stream as it is recorded (the
	// -watch-raw file). Writing never blocks the source: past a full buffer
	// events are left out of the file (counted), though still scored.
	Raw io.Writer
}

// Recording is a finished live window: the aggregated state and what the
// source reported about itself.
type Recording struct {
	Agg    *Aggregator
	Window Window
}

// Record watches this host for o.Duration, or until ctx ends (an
// interrupted window still returns what it recorded).
func Record(ctx context.Context, o RecordOptions) (*Recording, error) {
	started := time.Now().UTC()
	agg := NewAggregator(started, o.Limits, o.SelfPID)
	sink := agg.Add
	var raw *rawTee
	if o.Raw != nil {
		var err error
		raw, err = newRawTee(o.Raw, Header{Tool: "liveresponse-ng", Host: o.Host, RunID: o.RunID, OS: runtime.GOOS,
			Source: sourceName, Started: started, Duration: o.Duration.String(), SelfPID: o.SelfPID})
		if err != nil {
			return nil, err
		}
		sink = func(e Event) {
			agg.Add(e)
			raw.add(e)
		}
	}
	cpu0 := processCPU()
	wctx, cancel := context.WithTimeout(ctx, o.Duration)
	defer cancel()
	w, err := runSource(wctx, o, started, sink)
	ended := time.Now().UTC()
	agg.Close(ended)
	w.Interrupted = ctx.Err() != nil
	if w.Meta == nil {
		w.Meta = map[string]any{}
	}
	if cpu1 := processCPU(); cpu1 > 0 {
		secs := (cpu1 - cpu0).Seconds()
		w.Meta["cpu_seconds"] = round3(secs)
		if el := ended.Sub(started).Seconds(); el > 0 {
			w.Meta["cpu_percent_of_one_core"] = round3(100 * secs / el)
		}
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	w.Meta["heap_in_use_bytes"] = ms.HeapInuse
	if raw != nil {
		dropped := map[string]int64{}
		agg.mu.Lock()
		for k, n := range agg.dropped {
			dropped[k] = n
		}
		agg.mu.Unlock()
		if n, rerr := raw.close(Trailer{Ended: ended, Interrupted: w.Interrupted, Dropped: dropped}); rerr != nil {
			w.Errors = append(w.Errors, "watch-raw: "+rerr.Error())
		} else if n > 0 {
			w.Meta["raw_events_left_out"] = n
		}
	}
	if err != nil {
		return nil, err
	}
	return &Recording{Agg: agg, Window: w}, nil
}

// rawTee writes events to the raw stream from its own goroutine.
type rawTee struct {
	ch      chan Event
	done    chan error
	w       *StreamWriter
	sent    atomic.Int64
	dropped atomic.Int64
}

func newRawTee(out io.Writer, h Header) (*rawTee, error) {
	sw, err := NewStreamWriter(out, h)
	if err != nil {
		return nil, err
	}
	t := &rawTee{ch: make(chan Event, 1<<16), done: make(chan error, 1), w: sw}
	go func() {
		var werr error
		for e := range t.ch {
			if werr == nil {
				werr = sw.Write(e)
			}
		}
		t.done <- werr
	}()
	return t, nil
}

// add queues e; the source has stopped calling it before close.
func (t *rawTee) add(e Event) {
	if t.sent.Load() >= MaxStreamEvents {
		t.dropped.Add(1)
		return
	}
	select {
	case t.ch <- e:
		t.sent.Add(1)
	default:
		t.dropped.Add(1)
	}
}

func (t *rawTee) close(tr Trailer) (int64, error) {
	close(t.ch)
	dropped := t.dropped.Load()
	if err := <-t.done; err != nil {
		return dropped, err
	}
	if dropped > 0 {
		if tr.Dropped == nil {
			tr.Dropped = map[string]int64{}
		}
		tr.Dropped["raw_events_left_out"] = dropped
	}
	return dropped, t.w.Close(tr)
}
