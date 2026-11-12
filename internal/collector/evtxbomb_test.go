package collector

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// evtxTemplateBomb builds a one-chunk log whose single record nests `levels`
// template instances, each rendering the next `fanout` times.
func evtxTemplateBomb(levels, fanout int) []byte {
	le := binary.LittleEndian
	const defAt = 128
	body := []byte{0x0f, 0x01, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	nameOff := defAt + 24 + len(body) + 4
	body = le.AppendUint32(body, uint32(nameOff))
	body = append(body, 0, 0, 0, 0, 0, 0, 1, 0, 'E', 0, 0, 0) // inline name "E"
	body = append(body, 0x02)
	for i := 0; i < fanout; i++ {
		body = append(body, 0x0e, 0, 0, 0x21)
	}
	body = append(body, 0x04, 0x00)

	inst := func(inner []byte) []byte {
		b := []byte{0x0c, 1, 0, 0, 0, 0}
		b = le.AppendUint32(b, defAt)
		if inner == nil {
			return le.AppendUint32(b, 0)
		}
		b = le.AppendUint32(b, 1)
		b = le.AppendUint16(b, uint16(len(inner)))
		b = append(b, 0x21, 0)
		return append(b, inner...)
	}
	var v []byte
	for i := 0; i <= levels; i++ {
		v = inst(v)
	}

	chunk := make([]byte, evtxChunkLen)
	copy(chunk, evtxChunkMagic)
	le.PutUint64(chunk[evtxChunkFirstIDAt:], 1)
	le.PutUint32(chunk[defAt+20:], uint32(len(body)))
	copy(chunk[defAt+24:], body)
	rec := evtxChunkHdrLen
	le.PutUint32(chunk[rec:], evtxRecordMagic)
	le.PutUint32(chunk[rec+4:], uint32(24+len(v)+4))
	le.PutUint64(chunk[rec+8:], 1)
	copy(chunk[rec+24:], v)
	le.PutUint32(chunk[evtxFreeOffsetAt:], uint32(rec+24+len(v)+4))

	file := make([]byte, evtxHeaderLen, evtxHeaderLen+len(chunk))
	copy(file, evtxFileMagic)
	return append(file, chunk...)
}

// A crafted record nesting templates that each render the next twice used to
// render 2^levels elements: 40 levels from a record of about a kilobyte would
// run for days. The per-record budget stops it at once.
func TestEvtxTemplateBombIsBounded(t *testing.T) {
	start := time.Now()
	_, warns, err := parseEvtx(evtxTemplateBomb(40, 2), 0)
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("template bomb took %v", took)
	}
	if err != nil {
		t.Fatalf("parseEvtx: %v", err)
	}
	found := false
	for _, w := range warns {
		found = found || strings.Contains(w, "too many elements")
	}
	if !found {
		t.Fatalf("expected a warning about the record, got %v", warns)
	}
	// A shallow nest still renders.
	if recs, _, err := parseEvtx(evtxTemplateBomb(4, 2), 0); err != nil || len(recs) != 1 {
		t.Fatalf("shallow nest: %d records, %v", len(recs), err)
	}
}
