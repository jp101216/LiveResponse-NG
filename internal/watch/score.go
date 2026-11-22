package watch

import (
	"math"
	"sort"
	"time"
)

// Cutoff is the score at which a series becomes a finding; Strong is where a
// finding becomes suspect on its own.
const (
	Cutoff = 0.65
	Strong = 0.80
)

// Weights of the four components. Without sizes the first three are scaled
// to sum to 1.
const (
	// tightIQR: quartiles closer than this share of the median make skew moot.
	tightIQR = 0.1

	wSkew = 0.35
	wDisp = 0.35
	wCov  = 0.20
	wSize = 0.10
)

// Score is how regular a series of check-ins is, with its parts, so a report
// can show why a series scored what it did.
type Score struct {
	N        int     `json:"check_ins"`
	Median   float64 `json:"median_interval_s"`
	Q1       float64 `json:"q1_interval_s"`
	Q3       float64 `json:"q3_interval_s"`
	MAD      float64 `json:"mad_interval_s"`
	Skew     float64 `json:"s_skew"`
	Disp     float64 `json:"s_disp"`
	Cov      float64 `json:"s_cov"`
	Size     float64 `json:"s_size"`
	HasSizes bool    `json:"has_sizes"`
	Total    float64 `json:"score"`
}

// Jitter is the interval's spread relative to its median (MAD / median).
func (s Score) Jitter() float64 {
	if s.Median == 0 {
		return 0
	}
	return s.MAD / s.Median
}

// ScoreSeries scores check-in times (sorted, coalesced) and optional sizes
// (one per check-in, 0 = unknown) observed over window. ok is false when the
// series is too short to score: fewer than minN check-ins, or a window under
// three median intervals.
func ScoreSeries(times []time.Time, sizes []uint64, window time.Duration, minN int) (Score, bool) {
	n := len(times)
	if minN < 4 {
		minN = 4 // quartiles need at least three intervals
	}
	if n < minN || window <= 0 {
		return Score{N: n}, false
	}
	gaps := make([]float64, n-1)
	for i := 1; i < n; i++ {
		gaps[i-1] = times[i].Sub(times[i-1]).Seconds()
	}
	sort.Float64s(gaps)
	m := quantile(gaps, 0.5)
	if m <= 0 {
		return Score{N: n}, false
	}
	w := window.Seconds()
	if w < 3*m {
		return Score{N: n, Median: m}, false
	}
	q1, q3 := quantile(gaps, 0.25), quantile(gaps, 0.75)
	mad := medianAbsDev(gaps, m)

	s := Score{N: n, Median: m, Q1: q1, Q3: q3, MAD: mad}
	// Bowley skew. As in RITA, it is taken as 0 when the median equals a
	// quartile (intervals that are mostly one value). lrng also takes it as
	// 0 when the quartiles are within a tenth of the median of each other:
	// there, which side a second or two falls on is noise, not shape.
	if q3 > q1 && m != q1 && m != q3 && (q3-q1) >= tightIQR*m {
		s.Skew = clamp01(1 - math.Abs((q1+q3-2*m)/(q3-q1)))
	} else {
		s.Skew = 1
	}
	s.Disp = math.Max(0, 1-(mad/m)/0.5)
	s.Cov = math.Min(1, float64(n)*m/w)

	var known []float64
	for _, b := range sizes {
		if b > 0 {
			known = append(known, float64(b))
		}
	}
	// Sizes count only when most check-ins have one.
	if len(known) >= minN && len(known)*2 >= n {
		sort.Float64s(known)
		mb := quantile(known, 0.5)
		if mb > 0 {
			s.HasSizes = true
			s.Size = math.Max(0, 1-medianAbsDev(known, mb)/mb)
		}
	}
	if s.HasSizes {
		s.Total = wSkew*s.Skew + wDisp*s.Disp + wCov*s.Cov + wSize*s.Size
	} else {
		s.Total = (wSkew*s.Skew + wDisp*s.Disp + wCov*s.Cov) / (wSkew + wDisp + wCov)
	}
	s.Total = round3(s.Total)
	s.Skew, s.Disp, s.Cov, s.Size = round3(s.Skew), round3(s.Disp), round3(s.Cov), round3(s.Size)
	s.Median, s.Q1, s.Q3, s.MAD = round3(s.Median), round3(s.Q1), round3(s.Q3), round3(s.MAD)
	return s, true
}

// coalesce merges starts less than gap apart into one check-in (a beacon
// that opens two connections at once checks in once), summing their sizes.
func coalesce(times []time.Time, sizes []uint64, gap time.Duration) ([]time.Time, []uint64) {
	if len(times) == 0 {
		return nil, nil
	}
	idx := make([]int, len(times))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return times[idx[a]].Before(times[idx[b]]) })
	var ot []time.Time
	var osz []uint64
	for _, i := range idx {
		var sz uint64
		if i < len(sizes) {
			sz = sizes[i]
		}
		if len(ot) > 0 && times[i].Sub(ot[len(ot)-1]) < gap {
			osz[len(osz)-1] += sz
			continue
		}
		ot = append(ot, times[i])
		osz = append(osz, sz)
	}
	return ot, osz
}

// quantile of sorted xs by linear interpolation between order statistics.
func quantile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	pos := q * float64(len(xs)-1)
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return xs[lo]
	}
	return xs[lo] + (xs[hi]-xs[lo])*(pos-float64(lo))
}

func medianAbsDev(sorted []float64, m float64) float64 {
	dev := make([]float64, len(sorted))
	for i, x := range sorted {
		dev[i] = math.Abs(x - m)
	}
	sort.Float64s(dev)
	return quantile(dev, 0.5)
}

func clamp01(x float64) float64 { return math.Max(0, math.Min(1, x)) }

func round3(x float64) float64 { return math.Round(x*1000) / 1000 }
