package collector

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// chunkWithID builds a one-record chunk whose header carries firstID, the way a
// real log stamps each chunk with its first record identifier.
func chunkWithID(firstID uint64, rec []byte) []byte {
	c := encChunk(rec)
	binary.LittleEndian.PutUint64(c[evtxChunkFirstIDAt:], firstID)
	return c
}

// eventRec frames one event (by event id, optional EventData pairs) as a
// record with the given identifier.
func eventRec(id uint64, eventID int, channel string, data ...[2]string) []byte {
	children := []encNode{sysNode("Microsoft-Windows-Security-Auditing", eventID, channel)}
	if len(data) > 0 {
		children = append(children, dataNode(data...))
	}
	return encRecord(id, ftJun2021, encFragmentAt(recordBase, encNode{name: "Event", children: children}))
}

func recordIDs(t *testing.T, img []byte, newestFirst bool) []uint64 {
	t.Helper()
	var ids []uint64
	_, _, err := parseEvtxReader(bytesReaderAt(img), int64(len(img)), newestFirst, nil, func(r evtxRecord) bool {
		ids = append(ids, r.RecordID)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// TestParseEvtxWrappedLogOrder: in a full, circular log the newest chunks sit
// at the start of the file. Records must come out in identifier order, not
// file order.
func TestParseEvtxWrappedLogOrder(t *testing.T) {
	img := encFile(
		chunkWithID(300, eventRec(300, 4624, "Security")), // newest, wrapped to the front
		chunkWithID(100, eventRec(100, 4624, "Security")), // oldest
		chunkWithID(200, eventRec(200, 4624, "Security")),
	)
	if got := recordIDs(t, img, false); len(got) != 3 || got[0] != 100 || got[1] != 200 || got[2] != 300 {
		t.Fatalf("oldest-first order = %v, want [100 200 300]", got)
	}
	if got := recordIDs(t, img, true); len(got) != 3 || got[0] != 300 || got[1] != 200 || got[2] != 100 {
		t.Fatalf("newest-first order = %v, want [300 200 100]", got)
	}
}

// TestParseEvtxSkipsCorruptChunk: one bad chunk in the middle doesn't hide
// the chunks after it.
func TestParseEvtxSkipsCorruptChunk(t *testing.T) {
	bad := chunkWithID(150, eventRec(150, 4624, "Security"))
	copy(bad, "XXXXXXXX") // destroy the chunk signature
	img := encFile(
		chunkWithID(100, eventRec(100, 4624, "Security")),
		bad,
		chunkWithID(200, eventRec(200, 4624, "Security")),
	)
	if got := recordIDs(t, img, false); len(got) != 2 || got[0] != 100 || got[1] != 200 {
		t.Fatalf("records = %v, want [100 200] (the corrupt chunk skipped, not the rest)", got)
	}
}

func TestParseEvtxReaderStops(t *testing.T) {
	img := encFile(
		chunkWithID(1, eventRec(1, 4624, "Security")),
		chunkWithID(2, eventRec(2, 4624, "Security")),
		chunkWithID(3, eventRec(3, 4624, "Security")),
	)
	polls := 0
	var ids []uint64
	_, stopped, err := parseEvtxReader(bytesReaderAt(img), int64(len(img)), true,
		func() bool { polls++; return polls > 1 }, // allow one chunk, then "cancel"
		func(r evtxRecord) bool { ids = append(ids, r.RecordID); return true })
	if err != nil || !stopped || len(ids) != 1 || ids[0] != 3 {
		t.Fatalf("stopped=%v ids=%v err=%v; want the newest chunk only, then a stop", stopped, ids, err)
	}
}

// TestEventLogRetentionKeepsFindings: routine, finding-less events can't push
// a record with a finding out, and a later log is still read after the
// finding-less budget is spent.
func TestEventLogRetentionKeepsFindings(t *testing.T) {
	defer func(a, b, c int) { evtxMaxPerFile, evtxMaxKept, evtxMaxFlagged = a, b, c }(evtxMaxPerFile, evtxMaxKept, evtxMaxFlagged)
	evtxMaxPerFile, evtxMaxKept, evtxMaxFlagged = 2, 2, 10

	dir := t.TempDir()
	// Security: an old log clear, then a run of routine "account enabled"
	// events (always recorded, no finding) that overflows the per-log budget.
	var chunks [][]byte
	chunks = append(chunks, chunkWithID(1, eventRec(1, 1102, "Security")))
	for id := uint64(2); id <= 6; id++ {
		chunks = append(chunks, chunkWithID(id, eventRec(id, 4722, "Security", [2]string{"TargetUserName", "u"})))
	}
	sec := filepath.Join(dir, "Security.evtx")
	if err := os.WriteFile(sec, encFile(chunks...), 0o600); err != nil {
		t.Fatal(err)
	}
	// A later log whose only event is a Defender detection.
	def := filepath.Join(dir, "Microsoft-Windows-Windows Defender%4Operational.evtx")
	defRec := eventRec(9, 1116, "Microsoft-Windows-Windows Defender/Operational",
		[2]string{"Threat Name", "Trojan:Win32/Test"}, [2]string{"Path", `C:\Users\Public\x.exe`})
	if err := os.WriteFile(def, encFile(chunkWithID(9, defRec)), 0o600); err != nil {
		t.Fatal(err)
	}

	res := ParseEventLogFiles(context.Background(), []string{sec, def}, nil)
	var ids []uint64
	var haveClear, haveDefender bool
	for _, r := range res.Records {
		ids = append(ids, recordIDOf(r))
		haveClear = haveClear || hasFinding(r.Findings, "defense.clear_event_logs") != nil
		haveDefender = haveDefender || hasFinding(r.Findings, "eventlog.defender_detection") != nil
	}
	if !haveClear {
		t.Errorf("the log clear was evicted by routine events: kept ids %v", ids)
	}
	if !haveDefender {
		t.Errorf("the later Defender log was not read: kept ids %v", ids)
	}
	// Security keeps the clear plus the two most recent routine events, in log order.
	if len(ids) < 3 || ids[0] != 1 || ids[1] != 5 || ids[2] != 6 {
		t.Errorf("Security kept ids %v, want [1 5 6 ...] (the clear, then the most recent routine events)", ids)
	}
	if res.Meta["records_truncated"] != true || res.Meta["records_dropped"] != 3 {
		t.Errorf("truncation meta = %v / %v, want true / 3", res.Meta["records_truncated"], res.Meta["records_dropped"])
	}
}

func TestEventLogCancelledIsReported(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "Security.evtx")
	if err := os.WriteFile(p, encFile(chunkWithID(1, eventRec(1, 1102, "Security"))), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := ParseEventLogFiles(ctx, []string{p}, nil)
	found := false
	for _, e := range res.Errors {
		found = found || len(e) >= 9 && e[:9] == "cancelled"
	}
	if !found {
		t.Fatalf("a cancelled run must say so: %v", res.Errors)
	}
}

func TestEvent4672SystemAccountsNotRecorded(t *testing.T) {
	sys := newWinEvent(eventRecord(t, sysNode("Microsoft-Windows-Security-Auditing", 4672, "Security"),
		dataNode([2]string{"SubjectUserSid", "S-1-5-18"}, [2]string{"SubjectUserName", "SYSTEM"})))
	if _, _, keep := classifyWinEvent(sys, nil); keep {
		t.Error("a 4672 for LocalSystem is routine volume and should not be kept")
	}
	dwm := newWinEvent(eventRecord(t, sysNode("Microsoft-Windows-Security-Auditing", 4672, "Security"),
		dataNode([2]string{"SubjectUserSid", "S-1-5-90-0-1"}, [2]string{"SubjectUserName", "DWM-1"})))
	if _, _, keep := classifyWinEvent(dwm, nil); keep {
		t.Error("a 4672 for a DWM virtual account should not be kept")
	}
	admin := newWinEvent(eventRecord(t, sysNode("Microsoft-Windows-Security-Auditing", 4672, "Security"),
		dataNode([2]string{"SubjectUserSid", "S-1-5-21-1-2-3-500"}, [2]string{"SubjectUserName", "Administrator"})))
	if _, _, keep := classifyWinEvent(admin, nil); !keep {
		t.Error("a 4672 for a real administrator is the evidence of an admin logon and must be kept")
	}
}
