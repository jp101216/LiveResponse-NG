//go:build windows

package collector

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf8"
)

// TestEvtxParserMatchesWevtutil checks the EVTX parser against Windows' own
// event log API on the host's live System log: wevtutil renders the newest
// events as XML, and every one of them our parser also finds in System.evtx
// must agree on the event id, provider, channel and time. The portable tests
// parse logs built by our own encoder, which can only agree with our own
// reading of the format; this is the check against real data.
func TestEvtxParserMatchesWevtutil(t *testing.T) {
	if underWine() {
		t.Skip("no event log service under Wine")
	}
	out, err := exec.Command("wevtutil", "qe", "System", "/c:200", "/rd:true", "/f:xml").Output()
	if err != nil {
		t.Fatalf("wevtutil: %v", err)
	}
	// wevtutil writes in the console code page; the fields compared here are
	// ASCII, so replace anything else rather than trip the UTF-8 decoder.
	out = bytes.Map(func(r rune) rune {
		if r >= utf8.RuneSelf {
			return '?'
		}
		return r
	}, out)

	type wevtEvent struct {
		System struct {
			Provider struct {
				Name string `xml:"Name,attr"`
			} `xml:"Provider"`
			EventID     int `xml:"EventID"`
			TimeCreated struct {
				SystemTime string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
			EventRecordID uint64 `xml:"EventRecordID"`
			Channel       string `xml:"Channel"`
		} `xml:"System"`
	}
	want := map[uint64]wevtEvent{}
	dec := xml.NewDecoder(bytes.NewReader(out)) // one <Event> after another, no root
	for {
		var e wevtEvent
		if err := dec.Decode(&e); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("wevtutil XML: %v", err)
		}
		want[e.System.EventRecordID] = e
	}
	if len(want) == 0 {
		t.Skip("the System log is empty")
	}

	f, err := os.Open(filepath.Join(systemRoot(), `System32\winevt\Logs\System.evtx`))
	if err != nil {
		t.Fatalf("open the live System log: %v", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	scanned, matched, mismatched := 0, 0, 0
	warns, _, err := parseEvtxReader(f, info.Size(), true, func() bool { return false }, func(rec evtxRecord) bool {
		scanned++
		ev := newWinEvent(rec)
		w, ok := want[ev.RecordID]
		if !ok {
			return true
		}
		matched++
		wt, terr := time.Parse(time.RFC3339Nano, w.System.TimeCreated.SystemTime)
		d := ev.TimeCreated.Sub(wt)
		if ev.EventID != w.System.EventID || ev.Provider != w.System.Provider.Name ||
			ev.Channel != w.System.Channel || terr != nil || d > time.Microsecond || d < -time.Microsecond {
			mismatched++
			if mismatched <= 5 {
				t.Errorf("record %d: parsed event %d from %q in %q at %s; Windows says event %d from %q in %q at %s",
					ev.RecordID, ev.EventID, ev.Provider, ev.Channel, ev.TimeCreated.Format(time.RFC3339Nano),
					w.System.EventID, w.System.Provider.Name, w.System.Channel, w.System.TimeCreated.SystemTime)
			}
		}
		return true
	})
	if err != nil {
		t.Fatalf("parse the live System log: %v", err)
	}
	// The newest few events may not be flushed to the file yet; most must be.
	if matched < len(want)/2 {
		t.Errorf("only %d of Windows' newest %d System events were found in System.evtx", matched, len(want))
	}
	// A chunk still being written can yield a few warnings; more than that
	// means records the parser can't read.
	if len(warns) > 5+scanned/50 {
		t.Errorf("%d parse warnings over %d records, first: %q", len(warns), scanned, warns[:5])
	}
	t.Logf("parsed %d records; compared %d of the newest %d System events with wevtutil: %d differ; %d parse warnings",
		scanned, matched, len(want), mismatched, len(warns))
}
