//go:build windows

package watch

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/jp101216/liveresponse-ng/internal/collector"
)

const sourceName = "etw"

// SessionPrefix names lrng's ETW sessions; stale ones from crashed runs are
// stopped before a new one starts (ETW sessions outlive their process, and
// Windows allows 64 at once).
const SessionPrefix = "lrng-watch-"

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modtdh      = syscall.NewLazyDLL("tdh.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procStartTraceW            = modadvapi32.NewProc("StartTraceW")
	procControlTraceW          = modadvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2         = modadvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW             = modadvapi32.NewProc("OpenTraceW")
	procProcessTrace           = modadvapi32.NewProc("ProcessTrace")
	procCloseTrace             = modadvapi32.NewProc("CloseTrace")
	procQueryAllTracesW        = modadvapi32.NewProc("QueryAllTracesW")
	procTdhGetEventInformation = modtdh.NewProc("TdhGetEventInformation")
	procQueryDosDeviceW        = modkernel32.NewProc("QueryDosDeviceW")
)

// Providers and the events watch mode reads from each.
var (
	guidKernelProcess = syscall.GUID{Data1: 0x22FB2CD6, Data2: 0x0E7B, Data3: 0x422B, Data4: [8]byte{0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}}
	guidKernelNetwork = syscall.GUID{Data1: 0x7DD42A49, Data2: 0x5329, Data3: 0x4832, Data4: [8]byte{0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}}
	guidDNSClient     = syscall.GUID{Data1: 0x1C95126E, Data2: 0x7EEA, Data3: 0x49A9, Data4: [8]byte{0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D}}

	networkKinds = map[uint16]Kind{
		10: TCPSend, 11: TCPRecv, 12: TCPConnect, 13: TCPClose, 15: TCPAccept, // IPv4
		26: TCPSend, 27: TCPRecv, 28: TCPConnect, 29: TCPClose, 31: TCPAccept, // IPv6
		42: UDPSend, 43: UDPRecv, 58: UDPSend, 59: UDPRecv,
	}
)

const (
	eventTraceRealTimeMode    = 0x00000100
	wnodeFlagTracedGUID       = 0x00020000
	eventTraceControlQuery    = 0
	eventTraceControlStop     = 1
	processTraceModeRealTime  = 0x00000100
	processTraceModeEventRec  = 0x10000000
	eventControlEnable        = 1
	traceLevelVerbose         = 5
	keywordProcess            = 0x10
	keywordNetworkIPv4IPv6    = 0x30
	errorAlreadyExists        = 183
	errorInsufficientBuffer   = 122
	errorMoreData             = 234
	eventHeaderFlag32BitHdr   = 0x20
	eventHeaderFlag64BitHdr   = 0x40
	maxLoggerNameChars        = 1024
	filetimeEpochDelta        = 116444736000000000
	cmdlineQueueSize          = 4096
	maxRecordedDecodeErrors   = 8
	providerIndexProcess      = 1
	providerIndexNetwork      = 2
	providerIndexDNS          = 3
	tdhInfoFixedSize          = 112
	tdhPropertyInfoSize       = 24
	tdhInfoPropertyCountOff   = 100
	tdhInfoTopLevelCountOff   = 104
	stopWaitForProcessTrace   = 10 * time.Second
	defaultSessionBufferKiB   = 64
	defaultSessionMinBuffers  = 16
	defaultSessionMaxBuffers  = 128
	defaultSessionFlushTimerS = 1
)

// Struct layouts differ by pointer size: these are byte offsets from the
// SDK headers, for EVENT_TRACE_PROPERTIES and EVENT_TRACE_LOGFILEW.
var ptrSize = int(unsafe.Sizeof(uintptr(0)))

type layout struct {
	propsSize, logFileNameOff, loggerNameOff                    int
	logfileSize, lfLoggerName, lfProcessTraceMode, lfEventRecCB int
}

var lay = func() layout {
	if ptrSize == 8 {
		return layout{propsSize: 120, logFileNameOff: 112, loggerNameOff: 116,
			logfileSize: 448, lfLoggerName: 8, lfProcessTraceMode: 28, lfEventRecCB: 424}
	}
	return layout{propsSize: 120, logFileNameOff: 108, loggerNameOff: 112,
		logfileSize: 416, lfLoggerName: 4, lfProcessTraceMode: 20, lfEventRecCB: 400}
}()

// EVENT_TRACE_PROPERTIES field offsets common to both pointer sizes.
const (
	offWnodeBufferSize   = 0
	offWnodeClientCtx    = 40
	offWnodeFlags        = 44
	offBufferSize        = 48
	offMinimumBuffers    = 52
	offMaximumBuffers    = 56
	offLogFileMode       = 64
	offFlushTimer        = 68
	offEventsLost        = 88
	offBuffersWritten    = 92
	offLogBuffersLost    = 96
	offRealTimeBuffsLost = 100
)

type eventHeader struct {
	Size          uint16
	HeaderType    uint16
	Flags         uint16
	EventProperty uint16
	ThreadID      uint32
	ProcessID     uint32
	TimeStamp     int64
	ProviderID    syscall.GUID
	ID            uint16
	Version       uint8
	Channel       uint8
	Level         uint8
	Opcode        uint8
	Task          uint16
	Keyword       uint64
	ProcessorTime uint64
	ActivityID    syscall.GUID
}

// eventRecord is EVENT_RECORD; its pointer fields are unsafe.Pointer so the
// payload can be read without converting integers to pointers.
type eventRecord struct {
	Header            eventHeader
	BufferContext     uint32
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      unsafe.Pointer
	UserData          unsafe.Pointer
	UserContext       unsafe.Pointer
}

// u64 passes a 64-bit argument: one register on 64-bit Windows, two on x86.
func u64(v uint64) []uintptr {
	if ptrSize == 8 {
		return []uintptr{uintptr(v)}
	}
	return []uintptr{uintptr(uint32(v)), uintptr(uint32(v >> 32))}
}

// properties builds an EVENT_TRACE_PROPERTIES buffer with room for a name.
func properties() []byte {
	b := make([]byte, lay.propsSize+2*(maxLoggerNameChars+1)*2)
	binary.LittleEndian.PutUint32(b[offWnodeBufferSize:], uint32(len(b)))
	binary.LittleEndian.PutUint32(b[lay.loggerNameOff:], uint32(lay.propsSize))
	binary.LittleEndian.PutUint32(b[lay.logFileNameOff:], uint32(lay.propsSize+2*(maxLoggerNameChars+1)))
	return b
}

func controlTrace(name string, code uint32) ([]byte, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	props := properties()
	args := append(u64(0), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&props[0])), uintptr(code))
	r, _, _ := procControlTraceW.Call(args...)
	runtime.KeepAlive(props)
	if r != 0 {
		return props, syscall.Errno(r)
	}
	return props, nil
}

// StopStaleSessions stops lrng-watch-* sessions left by runs that crashed.
func StopStaleSessions() ([]string, error) {
	const max = 64
	bufs := make([][]byte, max)
	ptrs := make([]uintptr, max)
	for i := range bufs {
		bufs[i] = properties()
		ptrs[i] = uintptr(unsafe.Pointer(&bufs[i][0]))
	}
	var count uint32
	r, _, _ := procQueryAllTracesW.Call(uintptr(unsafe.Pointer(&ptrs[0])), max, uintptr(unsafe.Pointer(&count)))
	runtime.KeepAlive(bufs)
	if r != 0 && r != errorMoreData {
		return nil, fmt.Errorf("QueryAllTraces: %w", syscall.Errno(r))
	}
	var stopped []string
	for i := 0; i < int(count) && i < max; i++ {
		off := int(binary.LittleEndian.Uint32(bufs[i][lay.loggerNameOff:]))
		name := utf16z(bufs[i], off)
		if strings.HasPrefix(name, SessionPrefix) {
			if _, err := controlTrace(name, eventTraceControlStop); err == nil {
				stopped = append(stopped, name)
			}
		}
	}
	return stopped, nil
}

func utf16z(b []byte, off int) string {
	if off <= 0 || off >= len(b) {
		return ""
	}
	var u []uint16
	for j := off; j+1 < len(b); j += 2 {
		c := binary.LittleEndian.Uint16(b[j:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// consumer turns EVENT_RECORDs into Events. Callbacks arrive on the
// ProcessTrace thread, one at a time.
type consumer struct {
	sink     func(Event)
	self     uint32
	schemas  map[schemaKey]*tdhSchema
	devices  []devicePrefix
	cmdq     chan Event
	cmdMu    sync.RWMutex // held to send on cmdq; closing takes it exclusively
	cmdDone  bool
	cmdWG    sync.WaitGroup
	decodeN  map[string]int64
	errors   []string
	received atomic.Int64
	cmdSkip  atomic.Int64
	infoBuf  []byte
}

type schemaKey struct {
	provider uint8
	id       uint16
	version  uint8
}

var (
	callbackOnce sync.Once
	callbackPtr  uintptr
	active       atomic.Pointer[consumer]
)

func eventCallback(rec *eventRecord) uintptr {
	if c := active.Load(); c != nil && rec != nil {
		c.handle(rec)
	}
	return 0
}

func providerIndex(g *syscall.GUID) uint8 {
	switch *g {
	case guidKernelProcess:
		return providerIndexProcess
	case guidKernelNetwork:
		return providerIndexNetwork
	case guidDNSClient:
		return providerIndexDNS
	}
	return 0
}

func (c *consumer) handle(rec *eventRecord) {
	c.received.Add(1)
	prov := providerIndex(&rec.Header.ProviderID)
	id := rec.Header.ID
	var kind Kind
	switch prov {
	case providerIndexProcess:
		switch id {
		case 1:
			kind = ProcStart
		case 2:
			kind = ProcStop
		default:
			return
		}
	case providerIndexNetwork:
		k, ok := networkKinds[id]
		if !ok {
			return
		}
		kind = k
	case providerIndexDNS:
		if id != 3008 {
			return
		}
		kind = DNS
	default:
		return
	}
	s, err := c.schema(prov, rec)
	if err != nil {
		c.decodeError(prov, id, err)
		return
	}
	data := unsafe.Slice((*byte)(rec.UserData), int(rec.UserDataLength))
	ps := ptrSize
	switch {
	case rec.Header.Flags&eventHeaderFlag64BitHdr != 0:
		ps = 8
	case rec.Header.Flags&eventHeaderFlag32BitHdr != 0:
		ps = 4
	}
	e := Event{Time: filetime(rec.Header.TimeStamp), Kind: kind}
	switch prov {
	case providerIndexProcess:
		f, err := s.decode(data, ps, map[string]bool{"ProcessID": true, "ParentProcessID": true, "ImageName": true})
		pid, ok := f["ProcessID"].uint()
		if !ok {
			c.decodeError(prov, id, errOr(err, "no ProcessID"))
			return
		}
		e.PID = uint32(pid)
		if pp, ok := f["ParentProcessID"].uint(); ok {
			e.PPID = uint32(pp)
		}
		e.Image = c.dosPath(f["ImageName"].str())
		if kind == ProcStart && e.PID != c.self {
			c.cmdMu.RLock()
			queued := false
			if !c.cmdDone {
				select {
				case c.cmdq <- e: // the command line is read off this thread
					queued = true
				default:
					c.cmdSkip.Add(1)
				}
			}
			c.cmdMu.RUnlock()
			if queued {
				return
			}
		}
	case providerIndexNetwork:
		f, err := s.decode(data, ps, map[string]bool{"PID": true, "size": true, "daddr": true, "saddr": true, "dport": true, "sport": true})
		pid, ok := f["PID"].uint()
		daddr := f["daddr"].addr()
		dport, ok2 := f["dport"].uint()
		if !ok || !daddr.IsValid() || !ok2 {
			c.decodeError(prov, id, errOr(err, "no PID, daddr or dport"))
			return
		}
		sport, _ := f["sport"].uint()
		size, _ := f["size"].uint()
		e.PID = uint32(pid)
		e.Remote = netip.AddrPortFrom(daddr, uint16(dport))
		e.Local = netip.AddrPortFrom(f["saddr"].addr(), uint16(sport))
		e.Bytes = uint32(size)
	case providerIndexDNS:
		f, err := s.decode(data, ps, map[string]bool{"QueryName": true, "QueryType": true, "QueryStatus": true, "QueryResults": true})
		name := f["QueryName"].str()
		if name == "" {
			c.decodeError(prov, id, errOr(err, "no QueryName"))
			return
		}
		e.PID = rec.Header.ProcessID
		e.Query = name
		if qt, ok := f["QueryType"].uint(); ok {
			e.QType = uint16(qt)
		}
		if st, ok := f["QueryStatus"].uint(); ok {
			e.Status = uint32(st)
		}
		e.Answers = parseDNSResults(f["QueryResults"].str())
	}
	c.sink(e)
}

func errOr(err error, msg string) error {
	if err != nil {
		return err
	}
	return errors.New(msg)
}

func (c *consumer) decodeError(prov uint8, id uint16, err error) {
	key := fmt.Sprintf("%s/%d", [...]string{"", "kernel-process", "kernel-network", "dns-client"}[prov], id)
	c.decodeN[key]++
	if c.decodeN[key] == 1 && len(c.errors) < maxRecordedDecodeErrors {
		c.errors = append(c.errors, "decode "+key+": "+err.Error())
	}
}

// schema fetches an event version's layout from TDH once and caches it.
func (c *consumer) schema(prov uint8, rec *eventRecord) (*tdhSchema, error) {
	k := schemaKey{prov, rec.Header.ID, rec.Header.Version}
	if s, ok := c.schemas[k]; ok {
		if s == nil {
			return nil, errors.New("no schema")
		}
		return s, nil
	}
	s, err := c.fetchSchema(rec)
	c.schemas[k] = s // nil too: don't ask TDH again for every event
	return s, err
}

func (c *consumer) fetchSchema(rec *eventRecord) (*tdhSchema, error) {
	size := uint32(len(c.infoBuf))
	for attempt := 0; attempt < 3; attempt++ {
		var p uintptr
		if len(c.infoBuf) > 0 {
			p = uintptr(unsafe.Pointer(&c.infoBuf[0]))
		}
		r, _, _ := procTdhGetEventInformation.Call(uintptr(unsafe.Pointer(rec)), 0, 0, p, uintptr(unsafe.Pointer(&size)))
		if r == errorInsufficientBuffer {
			c.infoBuf = make([]byte, size)
			continue
		}
		if r != 0 {
			return nil, fmt.Errorf("TdhGetEventInformation: %w", syscall.Errno(r))
		}
		return parseEventInfo(c.infoBuf[:size])
	}
	return nil, errors.New("TdhGetEventInformation kept growing")
}

// parseEventInfo reads a TRACE_EVENT_INFO's property array.
func parseEventInfo(b []byte) (*tdhSchema, error) {
	if len(b) < tdhInfoFixedSize {
		return nil, errors.New("TRACE_EVENT_INFO too short")
	}
	n := int(binary.LittleEndian.Uint32(b[tdhInfoPropertyCountOff:]))
	top := int(binary.LittleEndian.Uint32(b[tdhInfoTopLevelCountOff:]))
	if n > maxTDHProps || top > n || tdhInfoFixedSize+n*tdhPropertyInfoSize > len(b) {
		return nil, fmt.Errorf("implausible TRACE_EVENT_INFO (%d properties, %d top level)", n, top)
	}
	s := &tdhSchema{top: top, props: make([]tdhProp, n)}
	for i := 0; i < n; i++ {
		p := b[tdhInfoFixedSize+i*tdhPropertyInfoSize:]
		flags := binary.LittleEndian.Uint32(p[0:])
		prop := tdhProp{
			name:   utf16z(b, int(binary.LittleEndian.Uint32(p[4:]))),
			flags:  flags,
			count:  binary.LittleEndian.Uint16(p[16:]),
			length: binary.LittleEndian.Uint16(p[18:]),
		}
		if flags&propStruct != 0 {
			prop.structStart = binary.LittleEndian.Uint16(p[8:])
			prop.structMembers = binary.LittleEndian.Uint16(p[10:])
		} else {
			prop.inType = binary.LittleEndian.Uint16(p[8:])
			prop.outType = binary.LittleEndian.Uint16(p[10:])
		}
		s.props[i] = prop
	}
	return s, nil
}

func filetime(ft int64) time.Time {
	return time.Unix(0, (ft-filetimeEpochDelta)*100).UTC()
}

// parseDNSResults reads DNS-Client's result list: "type:  5 cname;" entries
// for aliases and addresses (v4 as ::ffff:a.b.c.d), separated by ';'.
func parseDNSResults(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" || strings.HasPrefix(part, "type:") {
			continue
		}
		if ip, err := netip.ParseAddr(part); err == nil {
			out = append(out, ip.Unmap().String())
		}
	}
	return out
}

type devicePrefix struct{ device, drive string }

// devicePrefixes maps \Device\HarddiskVolumeN to its drive letter, since
// Kernel-Process reports NT device paths.
func devicePrefixes() []devicePrefix {
	var out []devicePrefix
	buf := make([]uint16, 1024)
	for l := 'A'; l <= 'Z'; l++ {
		drive := string(l) + ":"
		dp, _ := syscall.UTF16PtrFromString(drive)
		n, _, _ := procQueryDosDeviceW.Call(uintptr(unsafe.Pointer(dp)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n == 0 {
			continue
		}
		target := syscall.UTF16ToString(buf[:n])
		if target != "" {
			out = append(out, devicePrefix{strings.ToLower(target), drive})
		}
	}
	return out
}

func (c *consumer) dosPath(p string) string {
	if p == "" {
		return ""
	}
	lp := strings.ToLower(p)
	for _, d := range c.devices {
		if strings.HasPrefix(lp, d.device+`\`) {
			return d.drive + p[len(d.device):]
		}
	}
	if strings.HasPrefix(p, `\??\`) {
		return p[4:]
	}
	if strings.HasPrefix(lp, `\systemroot\`) {
		if root := os.Getenv("SystemRoot"); root != "" {
			return root + p[len(`\SystemRoot`):]
		}
	}
	return p
}

// runSource runs a real-time ETW session until ctx ends.
func runSource(ctx context.Context, o RecordOptions, started time.Time, sink func(Event)) (Window, error) {
	w := Window{Source: sourceName, Meta: map[string]any{}}
	if err := modadvapi32.Load(); err != nil {
		return w, err
	}
	if err := modtdh.Load(); err != nil {
		return w, fmt.Errorf("tdh.dll: %w", err)
	}
	if stopped, err := StopStaleSessions(); err != nil {
		w.Errors = append(w.Errors, "listing ETW sessions: "+err.Error())
	} else if len(stopped) > 0 {
		w.Meta["stale_sessions_stopped"] = stopped
	}
	name := SessionPrefix + o.RunID
	c := &consumer{sink: sink, self: o.SelfPID, schemas: map[schemaKey]*tdhSchema{},
		devices: devicePrefixes(), cmdq: make(chan Event, cmdlineQueueSize), decodeN: map[string]int64{}}

	// Seed the processes already running, so their connections are named.
	if procs, err := collector.RunningProcesses(); err == nil {
		for _, p := range procs {
			if p.PID != o.SelfPID {
				sink(Event{Time: started, Kind: ProcSeen, PID: p.PID, Image: p.Path})
			}
		}
	} else {
		w.Errors = append(w.Errors, "listing processes: "+err.Error())
	}

	// Command lines for new processes are read by a worker, not the callback.
	c.cmdWG.Add(1)
	go func() {
		defer c.cmdWG.Done()
		for e := range c.cmdq {
			e.CmdLine = collector.ProcessCommandLine(e.PID)
			sink(e)
		}
	}()
	defer func() {
		c.cmdMu.Lock()
		c.cmdDone = true
		close(c.cmdq)
		c.cmdMu.Unlock()
		c.cmdWG.Wait()
	}()

	props := properties()
	binary.LittleEndian.PutUint32(props[offWnodeClientCtx:], 1) // QPC; consumers get system time
	binary.LittleEndian.PutUint32(props[offWnodeFlags:], wnodeFlagTracedGUID)
	binary.LittleEndian.PutUint32(props[offBufferSize:], defaultSessionBufferKiB)
	binary.LittleEndian.PutUint32(props[offMinimumBuffers:], defaultSessionMinBuffers)
	binary.LittleEndian.PutUint32(props[offMaximumBuffers:], defaultSessionMaxBuffers)
	binary.LittleEndian.PutUint32(props[offLogFileMode:], eventTraceRealTimeMode)
	binary.LittleEndian.PutUint32(props[offFlushTimer:], defaultSessionFlushTimerS)
	namep, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return w, err
	}
	var session uint64
	r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(namep)), uintptr(unsafe.Pointer(&props[0])))
	if r == errorAlreadyExists {
		_, _ = controlTrace(name, eventTraceControlStop)
		props = properties()
		binary.LittleEndian.PutUint32(props[offWnodeClientCtx:], 1)
		binary.LittleEndian.PutUint32(props[offWnodeFlags:], wnodeFlagTracedGUID)
		binary.LittleEndian.PutUint32(props[offLogFileMode:], eventTraceRealTimeMode)
		binary.LittleEndian.PutUint32(props[offFlushTimer:], defaultSessionFlushTimerS)
		r, _, _ = procStartTraceW.Call(uintptr(unsafe.Pointer(&session)), uintptr(unsafe.Pointer(namep)), uintptr(unsafe.Pointer(&props[0])))
	}
	runtime.KeepAlive(props)
	if r != 0 {
		if r == 5 {
			return w, errors.New("starting the ETW session was denied: watch mode needs an elevated prompt (administrator or SYSTEM)")
		}
		return w, fmt.Errorf("StartTrace: %w", syscall.Errno(r))
	}
	w.Meta["etw_session"] = name
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		if p, err := controlTrace(name, eventTraceControlStop); err == nil {
			w.Meta["etw_events_lost"] = binary.LittleEndian.Uint32(p[offEventsLost:])
			w.Meta["etw_realtime_buffers_lost"] = binary.LittleEndian.Uint32(p[offRealTimeBuffsLost:])
			w.Meta["etw_buffers_written"] = binary.LittleEndian.Uint32(p[offBuffersWritten:])
			w.Meta["etw_log_buffers_lost"] = binary.LittleEndian.Uint32(p[offLogBuffersLost:])
		} else {
			w.Errors = append(w.Errors, "stopping the ETW session: "+err.Error())
		}
	}
	defer stop()

	enable := func(g *syscall.GUID, any uint64, what string, required bool) error {
		args := append(u64(session), uintptr(unsafe.Pointer(g)), eventControlEnable, traceLevelVerbose)
		args = append(args, u64(any)...)
		args = append(args, u64(0)...)
		args = append(args, 0, 0)
		r, _, _ := procEnableTraceEx2.Call(args...)
		if r != 0 {
			err := fmt.Errorf("enabling %s: %w", what, syscall.Errno(r))
			if required {
				return err
			}
			w.Errors = append(w.Errors, err.Error())
		}
		return nil
	}
	if err := enable(&guidKernelNetwork, keywordNetworkIPv4IPv6, "Microsoft-Windows-Kernel-Network", true); err != nil {
		return w, err
	}
	_ = enable(&guidKernelProcess, keywordProcess, "Microsoft-Windows-Kernel-Process", false)
	_ = enable(&guidDNSClient, ^uint64(0), "Microsoft-Windows-DNS-Client", false)

	callbackOnce.Do(func() { callbackPtr = syscall.NewCallback(eventCallback) })
	logfile := make([]byte, lay.logfileSize)
	*(*uintptr)(unsafe.Pointer(&logfile[lay.lfLoggerName])) = uintptr(unsafe.Pointer(namep))
	binary.LittleEndian.PutUint32(logfile[lay.lfProcessTraceMode:], processTraceModeRealTime|processTraceModeEventRec)
	*(*uintptr)(unsafe.Pointer(&logfile[lay.lfEventRecCB])) = callbackPtr
	if !active.CompareAndSwap(nil, c) {
		return w, errors.New("another watch is already running in this process")
	}
	defer active.Store(nil)

	r1, r2, e1 := procOpenTraceW.Call(uintptr(unsafe.Pointer(&logfile[0])))
	runtime.KeepAlive(namep)
	trace := uint64(r1)
	if ptrSize == 4 {
		trace |= uint64(r2) << 32
	}
	if trace == ^uint64(0) || trace == 0xFFFFFFFF {
		return w, fmt.Errorf("OpenTrace: %v", e1)
	}
	done := make(chan uintptr, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		h := trace
		r, _, _ := procProcessTrace.Call(uintptr(unsafe.Pointer(&h)), 1, 0, 0)
		done <- r
	}()

	select {
	case <-ctx.Done():
	case r := <-done: // the session ended on its own
		w.Errors = append(w.Errors, fmt.Sprintf("ProcessTrace returned early: %v", syscall.Errno(r)))
		done <- r
	}
	stop()
	select {
	case <-done:
	case <-time.After(stopWaitForProcessTrace):
		w.Errors = append(w.Errors, "ProcessTrace didn't return after the session stopped; closing it")
	}
	procCloseTrace.Call(u64(trace)...)
	select {
	case <-done:
	case <-time.After(stopWaitForProcessTrace):
	}
	runtime.KeepAlive(logfile)

	w.Meta["etw_events_received"] = c.received.Load()
	w.Meta["schemas_decoded"] = len(c.schemas)
	if n := c.cmdSkip.Load(); n > 0 {
		w.Meta["command_lines_skipped"] = n
	}
	if len(c.decodeN) > 0 {
		w.Meta["decode_errors"] = c.decodeN
	}
	w.Errors = append(w.Errors, c.errors...)
	return w, nil
}

func processCPU() time.Duration {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0
	}
	var c, e, k, u syscall.Filetime
	if err := syscall.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0
	}
	ticks := func(f syscall.Filetime) int64 { return int64(f.HighDateTime)<<32 | int64(f.LowDateTime) }
	return time.Duration((ticks(k) + ticks(u)) * 100)
}
