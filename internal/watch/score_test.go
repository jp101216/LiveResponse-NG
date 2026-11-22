package watch

import (
	"math"
	"math/rand"
	"sort"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC)

// series makes check-ins over win, with gaps drawn from next.
func series(start time.Time, win time.Duration, next func() float64, r *rand.Rand) []time.Time {
	at := start.Add(time.Duration(r.Float64() * 30 * float64(time.Second)))
	var ts []time.Time
	for at.Before(start.Add(win)) {
		ts = append(ts, at)
		at = at.Add(time.Duration(next() * float64(time.Second)))
	}
	return ts
}

// The spec's simulation: 300 trials per pattern over 15 minutes, no sizes.
// The formula has to separate beacons from random and bursty traffic.
func TestScoreSeparatesBeaconsFromNoise(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	win := 15 * time.Minute
	cases := []struct {
		name                 string
		gen                  func() []time.Time
		minMedian, maxMedian float64
		minFlag, maxFlag     int // percent
	}{
		{"60s ±20% jitter", func() []time.Time {
			return series(t0, win, func() float64 { return 60 * (0.8 + 0.4*r.Float64()) }, r)
		}, 0.78, 1, 90, 100},
		{"60s ±50% jitter", func() []time.Time {
			return series(t0, win, func() float64 { return 60 * (0.5 + r.Float64()) }, r)
		}, 0.66, 0.85, 60, 100},
		{"Poisson, 60s mean", func() []time.Time {
			return series(t0, win, func() float64 { return r.ExpFloat64() * 60 }, r)
		}, 0, 0.55, 0, 5},
		{"lognormal, 60s median", func() []time.Time {
			return series(t0, win, func() float64 { return 60 * math.Exp(r.NormFloat64()) }, r)
		}, 0, 0.55, 0, 8},
		{"bursty human use", func() []time.Time {
			var ts []time.Time
			for at := t0; at.Before(t0.Add(win)); at = at.Add(time.Duration(r.ExpFloat64() * 240 * float64(time.Second))) {
				for k := 3 + r.Intn(8); k > 0; k-- {
					at = at.Add(time.Duration((2 + 6*r.Float64()) * float64(time.Second)))
					ts = append(ts, at)
				}
			}
			return ts
		}, 0, 0.6, 0, 3},
	}
	for _, c := range cases {
		var scores []float64
		flagged := 0
		for i := 0; i < 300; i++ {
			ts, _ := coalesce(c.gen(), nil, time.Second)
			v := 0.0
			if s, ok := ScoreSeries(ts, nil, win, 6); ok {
				v = s.Total
			}
			scores = append(scores, v)
			if v >= Cutoff {
				flagged++
			}
		}
		sort.Float64s(scores)
		med, pct := scores[150], flagged*100/300
		if med < c.minMedian || med > c.maxMedian || pct < c.minFlag || pct > c.maxFlag {
			t.Errorf("%s: median %.2f (want %.2f–%.2f), flagged %d%% (want %d–%d%%)", c.name, med, c.minMedian, c.maxMedian, pct, c.minFlag, c.maxFlag)
		}
	}
}

func TestScoreExactBeacon(t *testing.T) {
	var ts []time.Time
	var sizes []uint64
	for i := 0; i < 15; i++ {
		ts = append(ts, t0.Add(time.Duration(i)*time.Minute))
		sizes = append(sizes, 812)
	}
	s, ok := ScoreSeries(ts, sizes, 15*time.Minute, 6)
	if !ok || s.Total != 1 || !s.HasSizes || s.Median != 60 || s.Jitter() != 0 {
		t.Fatalf("a perfect beacon scored %+v (ok %v)", s, ok)
	}
	// Sizes that vary wildly pull a regular series down, but only by their weight.
	for i := range sizes {
		sizes[i] = []uint64{100, 5000, 20000}[i%3]
	}
	s2, _ := ScoreSeries(ts, sizes, 15*time.Minute, 6)
	if s2.Size > 0.1 || s2.Total < 0.9 || s2.Total > 0.91 {
		t.Fatalf("varying sizes: %+v", s2)
	}
}

func TestScoreNeedsEnoughEvidence(t *testing.T) {
	var ts []time.Time
	for i := 0; i < 5; i++ {
		ts = append(ts, t0.Add(time.Duration(i)*time.Minute))
	}
	if _, ok := ScoreSeries(ts, nil, time.Hour, 6); ok {
		t.Error("scored 5 check-ins with a minimum of 6")
	}
	if _, ok := ScoreSeries(ts, nil, 2*time.Minute, 4); ok {
		t.Error("scored a series whose window is under three intervals")
	}
	if _, ok := ScoreSeries(ts, nil, time.Hour, 2); !ok {
		t.Error("a minimum under 4 is raised to 4, not refused")
	}
	same := []time.Time{t0, t0, t0, t0, t0, t0}
	if _, ok := ScoreSeries(same, nil, time.Hour, 4); ok {
		t.Error("scored simultaneous starts (median interval 0)")
	}
}

func TestCoalesce(t *testing.T) {
	ts := []time.Time{t0.Add(60 * time.Second), t0, t0.Add(200 * time.Millisecond), t0.Add(60*time.Second + 900*time.Millisecond)}
	sz := []uint64{10, 1, 2, 20}
	ct, cs := coalesce(ts, sz, time.Second)
	if len(ct) != 2 || !ct[0].Equal(t0) || cs[0] != 3 || cs[1] != 30 {
		t.Fatalf("coalesce = %v %v", ct, cs)
	}
}

// A tight beacon whose intervals take a few values (61, 61, 58 seconds) has
// its median on a quartile; Bowley skew there is ±1 by construction, and
// must not sink the score.
func TestScoreQuantizedTightBeacon(t *testing.T) {
	var ts []time.Time
	for i := 0; i < 15; i++ {
		ts = append(ts, t0.Add(time.Duration(i)*time.Minute+time.Duration(i%3)*time.Second))
	}
	s, ok := ScoreSeries(ts, nil, 15*time.Minute, 6)
	if !ok || s.Skew != 1 || s.Total < Strong {
		t.Fatalf("quantized beacon scored %+v", s)
	}
	// Two seconds of one-sided processing delay on a 60s sleep: tight, not skewed.
	r := rand.New(rand.NewSource(3))
	ts = ts[:0]
	at := t0
	for i := 0; i < 15; i++ {
		ts = append(ts, at)
		at = at.Add(60*time.Second + time.Duration(r.Float64()*2*float64(time.Second)))
	}
	if s, _ := ScoreSeries(ts, nil, 15*time.Minute, 6); s.Total < Strong {
		t.Fatalf("a 60s beacon with 0-2s delay scored %+v", s)
	}
}
