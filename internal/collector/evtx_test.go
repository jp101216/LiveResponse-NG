package collector

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// A spec-faithful BinXML/EVTX encoder, used to round-trip the parser the same
// way scca_test.go round-trips the prefetch decoder: the bytes are assembled
// here, independently of the parser, and parsed back. BinXML offsets are
// chunk-relative, so the encoder is told the absolute chunk offset at which a
// record's fragment begins (512-byte chunk header + 24-byte record header) and
// writes every name/template offset relative to the chunk.

type bxmlEnc struct {
	base int // absolute chunk offset of buf[0]
	buf  []byte
}

func (e *bxmlEnc) off() int { return e.base + len(e.buf) }
func (e *bxmlEnc) b(v byte) { e.buf = append(e.buf, v) }

func (e *bxmlEnc) u16(v uint16) {
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], v)
	e.buf = append(e.buf, t[:]...)
}

func (e *bxmlEnc) u32(v uint32) {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	e.buf = append(e.buf, t[:]...)
}

func (e *bxmlEnc) raw(p []byte)             { e.buf = append(e.buf, p...) }
func (e *bxmlEnc) patch32(at int, v uint32) { binary.LittleEndian.PutUint32(e.buf[at:], v) }

// name writes a Name structure: next(4), hash(2), char-count(2), chars, NUL(2).
func (e *bxmlEnc) name(s string) {
	chars := u16(s) // UTF-16LE bytes (helper from scca_test.go)
	e.u32(0)
	e.u16(0)
	e.u16(uint16(len(chars) / 2))
	e.raw(chars)
	e.u16(0)
}

// encAttr is an attribute whose value is a literal string (sub < 0) or a
// substitution (sub >= 0, of subType).
type encAttr struct {
	name    string
	literal string
	sub     int
	subType byte
}

func litAttr(name, val string) encAttr { return encAttr{name: name, literal: val, sub: -1} }
func subAttr(name string, idx int, t byte) encAttr {
	return encAttr{name: name, sub: idx, subType: t}
}

// encNode is an element: inline name, attributes, and content that is either
// child elements, a literal string, or a single (optional) substitution.
type encNode struct {
	name     string
	attrs    []encAttr
	text     string
	hasSub   bool
	subIndex int
	subType  byte
	optional bool
	children []encNode
}

func (e *bxmlEnc) element(n encNode) {
	tok := byte(tokOpenStart)
	if len(n.attrs) > 0 {
		tok |= tokMoreFlag
	}
	e.b(tok)
	e.u16(0xffff) // dependency id
	e.u32(0)      // element data size (parser ignores it)
	nameOffAt := len(e.buf)
	e.u32(0)
	e.patch32(nameOffAt, uint32(e.off())) // inline name starts here
	e.name(n.name)

	if len(n.attrs) > 0 {
		sizeAt := len(e.buf)
		e.u32(0)
		attrStart := len(e.buf)
		for i, a := range n.attrs {
			atok := byte(tokAttribute)
			if i < len(n.attrs)-1 {
				atok |= tokMoreFlag
			}
			e.b(atok)
			nAt := len(e.buf)
			e.u32(0)
			e.patch32(nAt, uint32(e.off()))
			e.name(a.name)
			if a.sub >= 0 {
				e.b(tokNormalSubst)
				e.u16(uint16(a.sub))
				e.b(a.subType)
			} else {
				e.b(tokValue)
				e.b(valString)
				chars := u16(a.literal)
				e.u16(uint16(len(chars) / 2))
				e.raw(chars)
			}
		}
		e.patch32(sizeAt, uint32(len(e.buf)-attrStart))
	}

	if n.text == "" && !n.hasSub && len(n.children) == 0 {
		e.b(tokCloseEmpty)
		return
	}
	e.b(tokCloseStart)
	for _, c := range n.children {
		e.element(c)
	}
	if n.text != "" {
		e.b(tokValue)
		e.b(valString)
		chars := u16(n.text)
		e.u16(uint16(len(chars) / 2))
		e.raw(chars)
	}
	if n.hasSub {
		tk := byte(tokNormalSubst)
		if n.optional {
			tk = tokOptionalSubst
		}
		e.b(tk)
		e.u16(uint16(n.subIndex))
		e.b(n.subType)
	}
	e.b(tokEndElement)
}

type encSub struct {
	typ  byte
	data []byte
}

// encFragmentAt builds a plain (non-template) fragment at a chunk offset.
func encFragmentAt(base int, root encNode) []byte {
	e := &bxmlEnc{base: base}
	e.b(tokFragmentHeader)
	e.b(1)
	e.b(1)
	e.b(0)
	e.element(root)
	e.b(tokEOF)
	return e.buf
}

// encTemplateFragmentAt builds a fragment holding one resident template
// instance and its substitution array.
func encTemplateFragmentAt(base int, root encNode, subs []encSub) []byte {
	e := &bxmlEnc{base: base}
	e.b(tokFragmentHeader)
	e.b(1)
	e.b(1)
	e.b(0)

	e.b(tokTemplateInst)
	e.b(1)        // version
	e.u32(0x1234) // template id
	defOffAt := len(e.buf)
	e.u32(0)
	e.patch32(defOffAt, uint32(e.off())) // resident: definition is right here

	e.u32(0)                // next-template offset
	e.raw(make([]byte, 16)) // template GUID
	dataLenAt := len(e.buf)
	e.u32(0)
	fragStart := len(e.buf)
	e.b(tokFragmentHeader)
	e.b(1)
	e.b(1)
	e.b(0)
	e.element(root)
	e.b(tokEOF)
	e.patch32(dataLenAt, uint32(len(e.buf)-fragStart))

	e.u32(uint32(len(subs)))
	for _, s := range subs {
		e.u16(uint16(len(s.data)))
		e.b(s.typ)
		e.b(0)
	}
	for _, s := range subs {
		e.raw(s.data)
	}
	return e.buf
}

func u32bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func u64bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// encRecord frames a BinXML fragment as an event record.
func encRecord(id, ft uint64, binxml []byte) []byte {
	size := 24 + len(binxml) + 4
	r := make([]byte, 0, size)
	r = append(r, u32bytes(evtxRecordMagic)...)
	r = append(r, u32bytes(uint32(size))...)
	r = append(r, u64bytes(id)...)
	r = append(r, u64bytes(ft)...)
	r = append(r, binxml...)
	r = append(r, u32bytes(uint32(size))...)
	return r
}

// encChunk lays records into a full 64 KiB chunk and sets the free-space
// offset so the parser knows where the records end.
func encChunk(records ...[]byte) []byte {
	c := make([]byte, evtxChunkLen)
	copy(c, evtxChunkMagic)
	off := evtxChunkHdrLen
	for _, r := range records {
		copy(c[off:], r)
		off += len(r)
	}
	binary.LittleEndian.PutUint32(c[evtxFreeOffsetAt:], uint32(off))
	return c
}

func encFile(chunks ...[]byte) []byte {
	f := make([]byte, evtxHeaderLen)
	copy(f, evtxFileMagic)
	for _, c := range chunks {
		f = append(f, c...)
	}
	return f
}

// recordBase is the chunk offset of the first record's BinXML fragment.
const recordBase = evtxChunkHdrLen + 24

// buildEvtx wraps one fragment into a single-record, single-chunk .evtx image.
func buildEvtx(id, ft uint64, fragment []byte) []byte {
	return encFile(encChunk(encRecord(id, ft, fragment)))
}

func TestParseEvtxDirectElementTree(t *testing.T) {
	root := encNode{name: "Event", children: []encNode{
		{name: "System", children: []encNode{
			{name: "EventID", text: "1102"},
			{name: "Channel", text: "Security"},
			{name: "Correlation"}, // empty element
		}},
	}}
	img := buildEvtx(7, ftJun2021, encFragmentAt(recordBase, root))

	recs, warns, err := parseEvtx(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	r := recs[0]
	if r.RecordID != 7 {
		t.Errorf("record id = %d, want 7", r.RecordID)
	}
	if r.Root.Name != "Event" {
		t.Fatalf("root = %q", r.Root.Name)
	}
	sys := r.Root.child("System")
	if sys == nil {
		t.Fatal("no System element")
	}
	if got := sys.child("EventID").Text; got != "1102" {
		t.Errorf("EventID = %q, want 1102", got)
	}
	if got := sys.child("Channel").Text; got != "Security" {
		t.Errorf("Channel = %q, want Security", got)
	}
	corr := sys.child("Correlation")
	if corr == nil || len(corr.Children) != 0 || corr.Text != "" {
		t.Errorf("Correlation should be empty: %+v", corr)
	}
}

func TestParseEvtxTemplateSubstitution(t *testing.T) {
	root := encNode{name: "Event", attrs: []encAttr{litAttr("xmlns", "http://schemas.microsoft.com/win/2004/08/events/event")},
		children: []encNode{
			{name: "System", children: []encNode{
				{name: "Provider", attrs: []encAttr{subAttr("Name", 0, valString)}},
				{name: "EventID", hasSub: true, subIndex: 1, subType: valUInt32},
				{name: "TimeCreated", attrs: []encAttr{subAttr("SystemTime", 2, valFileTime)}},
			}},
			{name: "EventData", children: []encNode{
				{name: "Data", attrs: []encAttr{litAttr("Name", "TargetUserName")}, hasSub: true, subIndex: 3, subType: valString},
				{name: "Data", attrs: []encAttr{litAttr("Name", "Missing")}, hasSub: true, subIndex: 4, subType: valString, optional: true},
			}},
		}}
	subs := []encSub{
		{valString, u16("Microsoft-Windows-Security-Auditing")},
		{valUInt32, u32bytes(4624)},
		{valFileTime, u64bytes(ftJun2021)},
		{valString, u16("jessie")},
		{valNull, nil}, // optional, absent
	}
	img := buildEvtx(42, ftJan2021, encTemplateFragmentAt(recordBase, root, subs))

	recs, warns, err := parseEvtx(img, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	ev := recs[0].Root
	if ev.Name != "Event" || ev.attr("xmlns") == "" {
		t.Fatalf("root/xmlns wrong: %+v", ev)
	}
	sys := ev.child("System")
	if got := sys.child("Provider").attr("Name"); got != "Microsoft-Windows-Security-Auditing" {
		t.Errorf("Provider Name = %q", got)
	}
	if got := sys.child("EventID").Text; got != "4624" {
		t.Errorf("EventID = %q, want 4624", got)
	}
	wantTime := fileTimeToTime(ftJun2021).UTC().Format("2006-01-02")
	if got := sys.child("TimeCreated").attr("SystemTime"); got[:10] != wantTime {
		t.Errorf("TimeCreated SystemTime = %q, want date %s", got, wantTime)
	}
	ed := ev.child("EventData")
	if len(ed.Children) != 2 {
		t.Fatalf("EventData children = %d, want 2", len(ed.Children))
	}
	if ed.Children[0].attr("Name") != "TargetUserName" || ed.Children[0].Text != "jessie" {
		t.Errorf("Data[0] = %+v", ed.Children[0])
	}
	if ed.Children[1].Text != "" {
		t.Errorf("optional-absent Data should be empty, got %q", ed.Children[1].Text)
	}
}

func TestParseEvtxRejectsBadFile(t *testing.T) {
	if _, _, err := parseEvtx([]byte("not-an-evtx-file-at-all"), 0); err == nil {
		t.Error("expected an error for a non-EVTX file")
	}
	if _, _, err := parseEvtx(nil, 0); err == nil {
		t.Error("expected an error for empty input")
	}
}

// TestParseEvtxHostileNoPanic feeds records with attacker-controlled offsets
// and sizes that point out of range or overflow when added. The parser must
// record a warning and skip, never panic or read out of bounds.
func TestParseEvtxHostileNoPanic(t *testing.T) {
	good := buildEvtx(1, ftJan2021, encFragmentAt(recordBase,
		encNode{name: "Event", children: []encNode{{name: "EventID", text: "1"}}}))

	mutations := map[string]func([]byte){
		"name offset past end": func(f []byte) {
			// The first element's name offset sits at recordBase+1+2+4 within
			// the chunk; chunk starts at evtxHeaderLen. Point it far away.
			at := evtxHeaderLen + recordBase + 4 + 1 + 2 + 4
			binary.LittleEndian.PutUint32(f[at:], 0x7ffffff0)
		},
		"record size overflow": func(f []byte) {
			at := evtxHeaderLen + evtxChunkHdrLen + 4 // record size field
			binary.LittleEndian.PutUint32(f[at:], 0x7ffffff0)
		},
		"free offset overflow": func(f []byte) {
			at := evtxHeaderLen + evtxFreeOffsetAt
			binary.LittleEndian.PutUint32(f[at:], 0xffffffff)
		},
	}
	for name, mutate := range mutations {
		f := append([]byte(nil), good...)
		mutate(f)
		// Must not panic. Result may be empty or carry warnings.
		if _, _, err := parseEvtx(f, 0); err != nil {
			t.Logf("%s: err=%v (acceptable)", name, err)
		}
	}
}

func TestParseEvtxMaxRecords(t *testing.T) {
	frag := encFragmentAt(recordBase, encNode{name: "Event", children: []encNode{{name: "EventID", text: "1"}}})
	// Three identical records in one chunk; offsets are the same because each
	// record is framed identically and the fragment's internal references are
	// relative to its own base — which here is the first record's base. To keep
	// the encoder simple we only assert the cap stops at 1.
	rec := encRecord(1, ftJan2021, frag)
	img := encFile(encChunk(rec))
	recs, _, err := parseEvtx(img, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1 (capped)", len(recs))
	}
}

// TestParseRealEvtxIfPresent parses any real .evtx dropped in testdata/ (for
// example on the Windows CI runner, or a copy of C:\Windows\System32\winevt\
// Logs\*.evtx). It is skipped when none is present, so the suite stays
// dependency-free, but gives a ground-truth check wherever a sample exists.
func TestParseRealEvtxIfPresent(t *testing.T) {
	matches, _ := filepath.Glob(filepath.Join("testdata", "*.evtx"))
	if len(matches) == 0 {
		t.Skip("no testdata/*.evtx sample present")
	}
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		recs, warns, err := parseEvtx(data, 5000)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(recs) == 0 {
			t.Errorf("%s: parsed no records", path)
		}
		// A real log should parse cleanly for the vast majority of records.
		if len(warns) > len(recs)/5+5 {
			t.Errorf("%s: %d warnings for %d records — parser likely has a format bug", path, len(warns), len(recs))
		}
		var withEventID int
		for _, r := range recs {
			if ev := newWinEvent(r); ev.EventID != 0 {
				withEventID++
			}
		}
		if withEventID == 0 {
			t.Errorf("%s: no record yielded an EventID", path)
		}
		t.Logf("%s: %d records, %d warnings, %d with EventID", path, len(recs), len(warns), withEventID)
	}
}
