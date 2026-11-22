package watch

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// StreamFormat names the -watch-raw file format, a JSON Lines file: a header
// line, one line per Event, and an end line when the window closed cleanly.
const StreamFormat = "lrng-watch"

// StreamVersion is bumped when a reader of an older version would misread
// a newer file.
const StreamVersion = 1

// Limits on a stream read by -watch-from.
const (
	MaxStreamEvents = 2_000_000
	maxLineBytes    = 1 << 20
)

// Header is a stream's first line.
type Header struct {
	Type     string    `json:"type"`
	Version  int       `json:"version"`
	Tool     string    `json:"tool,omitempty"`
	Host     string    `json:"host,omitempty"`
	RunID    string    `json:"run_id,omitempty"`
	OS       string    `json:"os,omitempty"`
	Source   string    `json:"source"`
	Started  time.Time `json:"started"`
	Duration string    `json:"duration"`
	SelfPID  uint32    `json:"self_pid,omitempty"`
}

// Trailer is a stream's last line, written when recording stopped.
type Trailer struct {
	Type        string           `json:"type"`
	Ended       time.Time        `json:"ended"`
	Interrupted bool             `json:"interrupted"`
	Events      int              `json:"events"`
	Dropped     map[string]int64 `json:"dropped,omitempty"`
}

// StreamWriter writes a stream. It is not safe for concurrent use.
type StreamWriter struct {
	w   *bufio.Writer
	enc *json.Encoder
	n   int
}

// NewStreamWriter writes h and returns a writer for the events that follow.
func NewStreamWriter(w io.Writer, h Header) (*StreamWriter, error) {
	h.Type, h.Version = StreamFormat, StreamVersion
	bw := bufio.NewWriterSize(w, 1<<16)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(h); err != nil {
		return nil, err
	}
	return &StreamWriter{w: bw, enc: enc}, nil
}

// Write appends one event.
func (s *StreamWriter) Write(e Event) error {
	s.n++
	return s.enc.Encode(e)
}

// Close writes the trailer and flushes. The event count is the writer's own.
func (s *StreamWriter) Close(t Trailer) error {
	t.Type, t.Events = "end", s.n
	if err := s.enc.Encode(t); err != nil {
		return err
	}
	return s.w.Flush()
}

// Stream is a stream read back by ReadStream.
type Stream struct {
	Header  Header
	Trailer *Trailer // nil when the file stops without one (a crashed run)
	Events  []Event
}

// ReadStream reads and validates a stream. Events must be in time order
// within a minute's slack, since ETW delivers each CPU's buffers separately.
func ReadStream(r io.Reader) (*Stream, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	var s Stream
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		if line == 1 {
			b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
			if err := strictUnmarshal(b, &s.Header); err != nil || s.Header.Type != StreamFormat {
				return nil, fmt.Errorf("line 1: not an lrng watch stream (written by -watch-raw)")
			}
			if s.Header.Version != StreamVersion {
				return nil, fmt.Errorf("line 1: stream version %d; this lrng reads version %d", s.Header.Version, StreamVersion)
			}
			if s.Header.Started.IsZero() {
				return nil, errors.New("line 1: the header has no start time")
			}
			continue
		}
		if s.Trailer != nil {
			return nil, fmt.Errorf("line %d: data after the end line", line)
		}
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(b, &probe); err != nil {
			return nil, fmt.Errorf("line %d: %v", line, err)
		}
		if probe.Type == "end" {
			var t Trailer
			if err := strictUnmarshal(b, &t); err != nil {
				return nil, fmt.Errorf("line %d: end line: %v", line, err)
			}
			s.Trailer = &t
			continue
		}
		if probe.Type != "" {
			return nil, fmt.Errorf("line %d: unexpected %q line", line, probe.Type)
		}
		if len(s.Events) >= MaxStreamEvents {
			return nil, fmt.Errorf("stream holds more than %d events", MaxStreamEvents)
		}
		var e Event
		if err := strictUnmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("line %d: %v", line, err)
		}
		if !knownKinds[e.Kind] {
			return nil, fmt.Errorf("line %d: unknown event kind %q", line, e.Kind)
		}
		if e.Time.Before(s.Header.Started.Add(-time.Minute)) {
			return nil, fmt.Errorf("line %d: event at %s is before the stream started", line, e.Time.Format(time.RFC3339))
		}
		s.Events = append(s.Events, e)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("line %d is over %d bytes", line+1, maxLineBytes)
		}
		return nil, err
	}
	if line == 0 {
		return nil, errors.New("the stream is empty")
	}
	if s.Trailer != nil && s.Trailer.Events != len(s.Events) {
		return nil, fmt.Errorf("the end line counts %d events but the stream holds %d", s.Trailer.Events, len(s.Events))
	}
	return &s, nil
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
