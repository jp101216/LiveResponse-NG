package collector

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// evtx.go — a dependency-free, read-only parser for the Windows XML Event Log
// (EVTX) container and its binary-XML (BinXML) encoding. No build tag: it
// decodes a plain byte slice, is bounds-checked against hostile input, and is
// unit-tested on any OS (see evtx_test.go). The live collector that feeds it
// the on-disk logs is Windows-only (eventlog_windows.go); offline parsing of a
// supplied .evtx works anywhere.
//
// Layout, in brief (see the public EVTX/BinXML documentation — libevtx — and
// the behaviour of python-evtx, which this follows):
//
//   - A 4096-byte file header ("ElfFile\0") followed by 64 KiB chunks.
//   - Each chunk has a 512-byte header ("ElfChnk\0") carrying a name-string and
//     template cache, then a run of event records.
//   - Each record ("**\0\0", 0x00002a2a) has a size, a 64-bit identifier, a
//     FILETIME, and a BinXML fragment.
//   - A BinXML fragment is a token stream: elements, attributes, typed values,
//     and template instances whose substitution arrays fill a cached template.
//
// Offsets inside BinXML (element/attribute names, template definitions) are
// relative to the start of the containing chunk, so the reader always holds the
// whole chunk and resolves back-references against it. Every offset and size in
// a record is attacker-controlled, so reads are bounds-checked and a malformed
// record yields a warning and is skipped, never a panic or an out-of-range
// slice.

const (
	evtxFileMagic   = "ElfFile\x00"
	evtxChunkMagic  = "ElfChnk\x00"
	evtxHeaderLen   = 4096
	evtxChunkLen    = 65536
	evtxChunkHdrLen = 512
	evtxRecordMagic = 0x00002a2a // "**\0\0"

	evtxFreeOffsetAt = 48 // chunk-relative offset of FreeSpaceOffset (end of records)

	bxmlMaxDepth = 256  // nesting / template-recursion guard
	bxmlMaxSubs  = 4096 // sanity cap on a substitution-array count
)

// BinXML token identifiers. The high 0x40 bit ("more data" / "has attributes")
// is masked off with &0x0f before comparing; the 0x40 bit is tested separately.
const (
	tokEOF            = 0x00
	tokOpenStart      = 0x01
	tokCloseStart     = 0x02
	tokCloseEmpty     = 0x03
	tokEndElement     = 0x04
	tokValue          = 0x05
	tokAttribute      = 0x06
	tokCDATA          = 0x07
	tokCharRef        = 0x08
	tokEntityRef      = 0x09
	tokPITarget       = 0x0a
	tokPIData         = 0x0b
	tokTemplateInst   = 0x0c
	tokNormalSubst    = 0x0d
	tokOptionalSubst  = 0x0e
	tokFragmentHeader = 0x0f
	tokMoreFlag       = 0x40
)

// BinXML value types (the subset that appears in event records).
const (
	valNull       = 0x00
	valString     = 0x01 // UTF-16LE
	valAnsiString = 0x02
	valInt8       = 0x03
	valUInt8      = 0x04
	valInt16      = 0x05
	valUInt16     = 0x06
	valInt32      = 0x07
	valUInt32     = 0x08
	valInt64      = 0x09
	valUInt64     = 0x0a
	valReal32     = 0x0b
	valReal64     = 0x0c
	valBool       = 0x0d
	valBinary     = 0x0e
	valGUID       = 0x0f
	valSizeT      = 0x10
	valFileTime   = 0x11
	valSysTime    = 0x12
	valSID        = 0x13
	valHexInt32   = 0x14
	valHexInt64   = 0x15
	valBinXML     = 0x21 // an embedded BinXML fragment
	valArrayFlag  = 0x80 // array of the base type
)

// evtxRecord is one parsed event: its 64-bit record identifier, the time the
// record was written (from the record header — the canonical event time lives
// in System/TimeCreated and is recovered in eventlog.go), and the rendered
// document root (normally <Event>). Root is nil if the record did not parse.
type evtxRecord struct {
	RecordID uint64
	Written  time.Time
	Root     *bxmlElement
}

// bxmlElement is a rendered BinXML element: an ordered attribute list, child
// elements, and the element's concatenated character/value content.
type bxmlElement struct {
	Name     string
	Attrs    []bxmlAttr
	Children []*bxmlElement
	Text     string
}

type bxmlAttr struct{ Name, Value string }

// child returns the first direct child element with the given (case-sensitive)
// name, or nil.
func (e *bxmlElement) child(name string) *bxmlElement {
	if e == nil {
		return nil
	}
	for _, c := range e.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// attr returns the value of the named attribute, or "".
func (e *bxmlElement) attr(name string) string {
	if e == nil {
		return ""
	}
	for _, a := range e.Attrs {
		if a.Name == name {
			return a.Value
		}
	}
	return ""
}

// substVal is one entry in a template instance's substitution array: its
// declared type, the raw bytes, and their absolute offset within the chunk (so
// an embedded-BinXML value can be rendered in place).
type substVal struct {
	typ    uint8
	data   []byte
	absOff int
}

// bxml is a cursor over one chunk. pos is the absolute offset within chunk;
// subs is the substitution array in scope (nil outside a template); err is
// sticky, so once a read runs past the end every further read is a no-op and
// the fragment is abandoned with whatever was decoded so far.
type bxml struct {
	chunk []byte
	pos   int
	subs  []substVal
	depth int
	err   error
}

func (b *bxml) fail(msg string) {
	if b.err == nil {
		b.err = errors.New("evtx: " + msg)
	}
}

// need reports whether n more bytes can be read at pos, written to avoid any
// pos+n addition that could overflow on a 32-bit build.
func (b *bxml) need(n int) bool {
	if b.err != nil {
		return false
	}
	if n < 0 || b.pos < 0 || b.pos > len(b.chunk) || n > len(b.chunk)-b.pos {
		b.fail("read past end of chunk")
		return false
	}
	return true
}

func (b *bxml) u8() uint8 {
	if !b.need(1) {
		return 0
	}
	v := b.chunk[b.pos]
	b.pos++
	return v
}

func (b *bxml) u16() uint16 {
	if !b.need(2) {
		return 0
	}
	v := le.Uint16(b.chunk[b.pos:])
	b.pos += 2
	return v
}

func (b *bxml) u32() uint32 {
	if !b.need(4) {
		return 0
	}
	v := le.Uint32(b.chunk[b.pos:])
	b.pos += 4
	return v
}

func (b *bxml) take(n int) []byte {
	if !b.need(n) {
		return nil
	}
	v := b.chunk[b.pos : b.pos+n]
	b.pos += n
	return v
}

// peek returns the next token byte without consuming it (0 at end).
func (b *bxml) peek() uint8 {
	if b.err != nil || b.pos < 0 || b.pos >= len(b.chunk) {
		return 0
	}
	return b.chunk[b.pos]
}

// nameAt reads a referenced Name structure at a chunk offset without moving the
// cursor: next-offset(4), hash(2), char-count(2), UTF-16LE chars, NUL(2).
func (b *bxml) nameAt(off int) string {
	if off < 0 || off+8 > len(b.chunk) {
		return ""
	}
	n := int(le.Uint16(b.chunk[off+6:]))
	start := off + 8
	if n < 0 || n*2 > len(b.chunk)-start {
		return ""
	}
	return decodeUTF16LE(b.chunk[start : start+n*2])
}

// readInlineName reads a Name structure at the cursor and advances past it.
func (b *bxml) readInlineName() string {
	start := b.pos
	if !b.need(8) {
		return ""
	}
	n := int(le.Uint16(b.chunk[start+6:]))
	nameBytes := 0
	if n > 0 {
		nameBytes = n * 2
	}
	total := 8 + nameBytes + 2 // + NUL terminator
	if !b.need(total) {
		return ""
	}
	s := decodeUTF16LE(b.chunk[start+8 : start+8+nameBytes])
	b.pos = start + total
	return s
}

// evtxMaxWarnings bounds the per-image warning list so a wholly corrupt file
// can't grow it without limit; further problems are dropped (the caller reports
// the record/warning counts either way).
const evtxMaxWarnings = 500

// parseEvtx parses an .evtx image into records (capped by maxRecords; <= 0 is
// no cap). It is a convenience wrapper over parseEvtxStream, used by the tests;
// the collector streams instead so a large log is never all in memory at once.
func parseEvtx(data []byte, maxRecords int) (recs []evtxRecord, warnings []string, err error) {
	warnings, err = parseEvtxStream(data, func(r evtxRecord) bool {
		recs = append(recs, r)
		return maxRecords <= 0 || len(recs) < maxRecords
	})
	return recs, warnings, err
}

// parseEvtxStream walks every record in an .evtx image, calling emit for each
// one; emit returns false to stop. Per-record/chunk problems are collected as
// warnings (capped); a fatal error is returned only for a bad file header.
func parseEvtxStream(data []byte, emit func(evtxRecord) bool) (warnings []string, err error) {
	if len(data) < 8 || string(data[:8]) != evtxFileMagic {
		return nil, errors.New("evtx: missing ElfFile signature")
	}
	for base := evtxHeaderLen; base+evtxChunkHdrLen <= len(data); base += evtxChunkLen {
		if string(data[base:base+8]) != evtxChunkMagic {
			break // padding or the end of the written chunks
		}
		end := base + evtxChunkLen
		if end > len(data) {
			end = len(data) // a dirty/truncated final chunk
		}
		if stop := parseChunkRecords(data[base:end], &warnings, emit); stop {
			break
		}
	}
	return warnings, nil
}

// warn appends a bounded warning.
func warn(warnings *[]string, msg string) {
	if len(*warnings) < evtxMaxWarnings {
		*warnings = append(*warnings, msg)
	}
}

// parseChunkRecords walks the records in one chunk slice (index 0 = chunk
// start, as BinXML offsets expect). It returns true if emit asked to stop.
func parseChunkRecords(chunk []byte, warnings *[]string, emit func(evtxRecord) bool) bool {
	if len(chunk) < evtxChunkHdrLen {
		return false
	}
	freeOff := int(le.Uint32(chunk[evtxFreeOffsetAt:]))
	if freeOff < evtxChunkHdrLen || freeOff > len(chunk) {
		freeOff = len(chunk)
	}
	for off := evtxChunkHdrLen; off+24 <= freeOff; {
		if le.Uint32(chunk[off:]) != evtxRecordMagic {
			break
		}
		size := int(le.Uint32(chunk[off+4:]))
		if size < 28 || size > len(chunk)-off {
			warn(warnings, fmt.Sprintf("evtx: implausible record size %d at chunk offset %d", size, off))
			break
		}
		rec := evtxRecord{
			RecordID: le.Uint64(chunk[off+8:]),
			Written:  fileTimeToTime(le.Uint64(chunk[off+16:])),
		}
		r := &bxml{chunk: chunk, pos: off + 24}
		rec.Root = r.parseFragment()
		if r.err != nil {
			warn(warnings, fmt.Sprintf("evtx: record %d: %v", rec.RecordID, r.err))
		}
		if rec.Root != nil && !emit(rec) {
			return true
		}
		off += size
	}
	return false
}

// parseFragment parses a BinXML fragment: an optional fragment header followed
// by a single root produced by an element or a template instance.
func (b *bxml) parseFragment() *bxmlElement {
	if b.depth++; b.depth > bxmlMaxDepth {
		b.fail("fragment nesting too deep")
		return nil
	}
	defer func() { b.depth-- }()

	if b.peek() == tokFragmentHeader {
		b.pos += 4 // token, major, minor, flags
	}
	switch t := b.u8(); t & 0x0f {
	case tokOpenStart:
		return b.parseElement(t)
	case tokTemplateInst:
		return b.parseTemplateInstance()
	default:
		return nil
	}
}

// parseElement parses an OpenStartElement (tok is the raw token, so tok&0x40
// signals an attribute list) through its matching close, returning the element.
func (b *bxml) parseElement(tok uint8) *bxmlElement {
	if b.depth++; b.depth > bxmlMaxDepth {
		b.fail("element nesting too deep")
		return nil
	}
	defer func() { b.depth-- }()

	_ = b.u16() // dependency identifier (unused)
	_ = b.u32() // element data size (unused; we parse linearly)
	nameOff := int(b.u32())
	el := &bxmlElement{}
	if nameOff == b.pos {
		el.Name = b.readInlineName()
	} else {
		el.Name = b.nameAt(nameOff)
	}

	if tok&tokMoreFlag != 0 {
		attrSize := int(b.u32())
		attrEnd := b.pos + attrSize
		if attrSize < 0 || attrEnd > len(b.chunk) {
			attrEnd = len(b.chunk)
		}
		b.parseAttributes(el, attrEnd)
		if b.err == nil {
			b.pos = attrEnd // land exactly after the attribute list
		}
	}

	switch b.u8() & 0x0f {
	case tokCloseStart:
		b.parseContent(el)
	case tokCloseEmpty:
		// empty element: no content
	default:
		b.fail("expected a close-start or close-empty token")
	}
	return el
}

// parseAttributes reads the attribute list in [pos, attrEnd).
func (b *bxml) parseAttributes(el *bxmlElement, attrEnd int) {
	for b.err == nil && b.pos < attrEnd {
		t := b.u8()
		if t&0x0f != tokAttribute {
			b.fail("expected an attribute token")
			return
		}
		nameOff := int(b.u32())
		var name string
		if nameOff == b.pos {
			name = b.readInlineName()
		} else {
			name = b.nameAt(nameOff)
		}
		el.Attrs = append(el.Attrs, bxmlAttr{Name: name, Value: b.parseAttrValue(attrEnd)})
		if t&tokMoreFlag == 0 {
			return // last attribute
		}
	}
}

// parseAttrValue renders the value tokens that make up one attribute value,
// stopping at the next attribute token, a close token or attrEnd.
func (b *bxml) parseAttrValue(attrEnd int) string {
	var sb strings.Builder
	for b.err == nil && b.pos < attrEnd {
		switch b.peek() & 0x0f {
		case tokValue:
			b.u8()
			sb.WriteString(b.parseValueToken())
		case tokNormalSubst, tokOptionalSubst:
			b.u8()
			sb.WriteString(b.readSubstText())
		case tokCharRef:
			b.u8()
			sb.WriteRune(rune(b.u16()))
		case tokEntityRef:
			b.u8()
			sb.WriteString(b.readEntityRef())
		default:
			return sb.String() // an attribute or close token: value done
		}
	}
	return sb.String()
}

// parseContent reads an element's content until its EndElement.
func (b *bxml) parseContent(parent *bxmlElement) {
	for b.err == nil {
		t := b.u8()
		switch t & 0x0f {
		case tokEndElement, tokEOF:
			return
		case tokOpenStart:
			if c := b.parseElement(t); c != nil {
				parent.Children = append(parent.Children, c)
			}
		case tokValue:
			parent.Text += b.parseValueToken()
		case tokNormalSubst, tokOptionalSubst:
			b.applySubst(parent)
		case tokTemplateInst:
			if c := b.parseTemplateInstance(); c != nil {
				parent.Children = append(parent.Children, c)
			}
		case tokCharRef:
			parent.Text += string(rune(b.u16()))
		case tokEntityRef:
			parent.Text += b.readEntityRef()
		case tokCDATA:
			parent.Text += b.parseCDATA()
		default:
			b.fail(fmt.Sprintf("unknown content token 0x%02x", t))
			return
		}
	}
}

// applySubst resolves a substitution token in content position: a scalar value
// is appended to the parent's text; an embedded-BinXML value is parsed and its
// element attached as a child.
func (b *bxml) applySubst(parent *bxmlElement) {
	idx := int(b.u16())
	_ = b.u8() // declared value type (the array entry's type is authoritative)
	if idx < 0 || idx >= len(b.subs) {
		return
	}
	text, el := b.renderValue(b.subs[idx])
	if el != nil {
		parent.Children = append(parent.Children, el)
		return
	}
	parent.Text += text
}

// readSubstText resolves a substitution token to its scalar text (used for
// attribute values; an embedded-BinXML value renders empty here).
func (b *bxml) readSubstText() string {
	idx := int(b.u16())
	_ = b.u8()
	if idx < 0 || idx >= len(b.subs) {
		return ""
	}
	text, _ := b.renderValue(b.subs[idx])
	return text
}

// parseTemplateInstance parses a template instance (resident definition or a
// back-reference to one earlier in the chunk), reads its substitution array,
// advances the cursor past the whole instance, and renders the template body
// with the substitutions in scope.
func (b *bxml) parseTemplateInstance() *bxmlElement {
	if b.depth++; b.depth > bxmlMaxDepth {
		b.fail("template nesting too deep")
		return nil
	}
	defer func() { b.depth-- }()

	instStart := b.pos - 1 // the TemplateInstance token
	_ = b.u8()             // version / unknown
	_ = b.u32()            // template identifier
	defOff := int(b.u32())
	resident := defOff > instStart

	// Template definition header: next-offset(4), GUID(16), data-length(4).
	if defOff < 0 || defOff+24 > len(b.chunk) {
		b.fail("template definition out of range")
		return nil
	}
	dataLen := int(le.Uint32(b.chunk[defOff+20:]))
	fragAt := defOff + 24
	if dataLen < 0 || dataLen > len(b.chunk)-fragAt {
		b.fail("template fragment out of range")
		return nil
	}

	substAt := b.pos // a referenced instance: substitutions follow the header
	if resident {
		substAt = fragAt + dataLen // a resident instance: they follow the body
	}
	subs, end := b.readSubstArray(substAt)
	if b.err != nil {
		return nil
	}
	b.pos = end // continue after the instance

	body := &bxml{chunk: b.chunk, pos: fragAt, subs: subs, depth: b.depth}
	root := body.parseFragment()
	if body.err != nil && b.err == nil {
		b.err = body.err
	}
	return root
}

// readSubstArray reads a substitution array at a chunk offset: count(4), then
// count × (size(2), type(1), reserved(1)) descriptors, then the values. It
// returns the values and the offset just past them.
func (b *bxml) readSubstArray(at int) ([]substVal, int) {
	if at < 0 || at+4 > len(b.chunk) {
		b.fail("substitution array out of range")
		return nil, at
	}
	count := int(le.Uint32(b.chunk[at:]))
	if count < 0 || count > bxmlMaxSubs {
		b.fail("implausible substitution count")
		return nil, at
	}
	descAt := at + 4
	if count > (len(b.chunk)-descAt)/4 {
		b.fail("substitution descriptors out of range")
		return nil, at
	}
	subs := make([]substVal, count)
	p := descAt + count*4
	for i := 0; i < count; i++ {
		d := descAt + i*4
		size := int(le.Uint16(b.chunk[d:]))
		typ := b.chunk[d+2]
		if size < 0 || size > len(b.chunk)-p {
			b.fail("substitution value out of range")
			return subs, p
		}
		subs[i] = substVal{typ: typ, data: b.chunk[p : p+size], absOff: p}
		p += size
	}
	return subs, p
}

// renderValue renders a substitution value: a scalar returns text; an
// embedded-BinXML value returns a parsed element.
func (b *bxml) renderValue(sv substVal) (string, *bxmlElement) {
	switch {
	case sv.typ == valBinXML:
		sub := &bxml{chunk: b.chunk, pos: sv.absOff, depth: b.depth + 1}
		return "", sub.parseFragment()
	case sv.typ&valArrayFlag != 0:
		return renderArray(sv.typ&^valArrayFlag, sv.data), nil
	default:
		return renderScalar(sv.typ, sv.data), nil
	}
}

// parseValueToken reads an inline Value token's payload (already past the token
// byte): a type, then its data. Strings carry a UTF-16 char count; fixed types
// are read by their size. An unsupported inline type aborts the fragment.
func (b *bxml) parseValueToken() string {
	typ := b.u8()
	switch typ {
	case valNull:
		return ""
	case valString:
		n := int(b.u16())
		return decodeUTF16LE(b.take(n * 2))
	case valAnsiString:
		n := int(b.u16())
		return strings.TrimRight(string(b.take(n)), "\x00")
	default:
		if sz, ok := fixedTypeSize(typ); ok {
			return renderScalar(typ, b.take(sz))
		}
		b.fail(fmt.Sprintf("unsupported inline value type 0x%02x", typ))
		return ""
	}
}

func (b *bxml) parseCDATA() string {
	n := int(b.u16())
	return decodeUTF16LE(b.take(n * 2))
}

func (b *bxml) readEntityRef() string {
	off := int(b.u32())
	var name string
	if off == b.pos {
		name = b.readInlineName()
	} else {
		name = b.nameAt(off)
	}
	switch name {
	case "lt":
		return "<"
	case "gt":
		return ">"
	case "amp":
		return "&"
	case "quot":
		return "\""
	case "apos":
		return "'"
	case "":
		return ""
	default:
		return "&" + name + ";"
	}
}

// renderScalar formats one typed value as text.
func renderScalar(typ uint8, d []byte) string {
	switch typ {
	case valNull:
		return ""
	case valString:
		return decodeUTF16LE(d)
	case valAnsiString:
		return strings.TrimRight(string(d), "\x00")
	case valInt8:
		if len(d) >= 1 {
			return strconv.FormatInt(int64(int8(d[0])), 10)
		}
	case valUInt8:
		if len(d) >= 1 {
			return strconv.FormatUint(uint64(d[0]), 10)
		}
	case valInt16:
		if len(d) >= 2 {
			return strconv.FormatInt(int64(int16(le.Uint16(d))), 10)
		}
	case valUInt16:
		if len(d) >= 2 {
			return strconv.FormatUint(uint64(le.Uint16(d)), 10)
		}
	case valInt32:
		if len(d) >= 4 {
			return strconv.FormatInt(int64(int32(le.Uint32(d))), 10)
		}
	case valUInt32:
		if len(d) >= 4 {
			return strconv.FormatUint(uint64(le.Uint32(d)), 10)
		}
	case valInt64:
		if len(d) >= 8 {
			return strconv.FormatInt(int64(le.Uint64(d)), 10)
		}
	case valUInt64:
		if len(d) >= 8 {
			return strconv.FormatUint(le.Uint64(d), 10)
		}
	case valReal32:
		if len(d) >= 4 {
			return strconv.FormatFloat(float64(math.Float32frombits(le.Uint32(d))), 'g', -1, 32)
		}
	case valReal64:
		if len(d) >= 8 {
			return strconv.FormatFloat(math.Float64frombits(le.Uint64(d)), 'g', -1, 64)
		}
	case valBool:
		for _, c := range d {
			if c != 0 {
				return "true"
			}
		}
		return "false"
	case valBinary:
		return fmt.Sprintf("%x", d)
	case valGUID:
		return formatGUID(d)
	case valSizeT:
		if len(d) >= 8 {
			return strconv.FormatUint(le.Uint64(d), 10)
		}
		if len(d) >= 4 {
			return strconv.FormatUint(uint64(le.Uint32(d)), 10)
		}
	case valFileTime:
		if len(d) >= 8 {
			if t := fileTimeToTime(le.Uint64(d)); !t.IsZero() {
				return t.UTC().Format(time.RFC3339Nano)
			}
		}
	case valSysTime:
		return formatSysTime(d)
	case valSID:
		return formatSID(d)
	case valHexInt32:
		if len(d) >= 4 {
			return fmt.Sprintf("0x%x", le.Uint32(d))
		}
	case valHexInt64:
		if len(d) >= 8 {
			return fmt.Sprintf("0x%x", le.Uint64(d))
		}
	}
	return ""
}

// renderArray formats an array value (base type bt) as a comma-separated list.
func renderArray(bt uint8, d []byte) string {
	if bt == valString {
		return strings.Join(splitUTF16Z(d), ", ")
	}
	sz, ok := fixedTypeSize(bt)
	if !ok || sz == 0 {
		return fmt.Sprintf("%x", d)
	}
	var parts []string
	for i := 0; i+sz <= len(d); i += sz {
		parts = append(parts, renderScalar(bt, d[i:i+sz]))
	}
	return strings.Join(parts, ", ")
}

// fixedTypeSize returns the byte width of a fixed-width value type.
func fixedTypeSize(t uint8) (int, bool) {
	switch t {
	case valInt8, valUInt8:
		return 1, true
	case valInt16, valUInt16:
		return 2, true
	case valInt32, valUInt32, valReal32, valHexInt32, valBool:
		return 4, true
	case valInt64, valUInt64, valReal64, valFileTime, valHexInt64:
		return 8, true
	case valGUID, valSysTime:
		return 16, true
	}
	return 0, false
}

// formatGUID renders a 16-byte GUID as {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}.
func formatGUID(d []byte) string {
	if len(d) < 16 {
		return ""
	}
	return fmt.Sprintf("{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
		le.Uint32(d[0:]), le.Uint16(d[4:]), le.Uint16(d[6:]),
		d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15])
}

// formatSysTime renders a 16-byte SYSTEMTIME (year, month, day-of-week, day,
// hour, minute, second, millisecond — each a u16) in UTC.
func formatSysTime(d []byte) string {
	if len(d) < 16 {
		return ""
	}
	t := time.Date(int(le.Uint16(d[0:])), time.Month(le.Uint16(d[2:])), int(le.Uint16(d[6:])),
		int(le.Uint16(d[8:])), int(le.Uint16(d[10:])), int(le.Uint16(d[12:])),
		int(le.Uint16(d[14:]))*int(time.Millisecond), time.UTC)
	return t.Format(time.RFC3339Nano)
}

// formatSID renders a binary SID as S-R-IA-SA1-SA2-...
func formatSID(d []byte) string {
	if len(d) < 8 {
		return ""
	}
	rev := d[0]
	subCount := int(d[1])
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = authority<<8 | uint64(d[i])
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", rev, authority)
	p := 8
	for i := 0; i < subCount; i++ {
		if p+4 > len(d) {
			break
		}
		fmt.Fprintf(&sb, "-%d", le.Uint32(d[p:]))
		p += 4
	}
	return sb.String()
}
