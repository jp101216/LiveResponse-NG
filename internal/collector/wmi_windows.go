//go:build windows

package collector

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// WMI permanent event subscriptions are read live over COM: there is no file
// or registry key to parse, the CIM repository format is undocumented, and a
// live query is what the PowerShell predecessor (Get-WmiObject) and every
// hunting playbook use. lrng has no third-party dependency, so the COM plumbing
// is hand-rolled on top of ole32/oleaut32 and raw vtable dispatch here; the
// enumeration hands plain Go structs to the portable rules in wmirules.go,
// which are unit-tested on any OS. This file is exercised end-to-end on the
// Windows CI runner (see wmi_windows_test.go and the default-collector sweep).

// COM interface pointers are kept as unsafe.Pointer (never a bare uintptr) so
// every conversion back for a syscall is the sanctioned uintptr(Pointer) form.

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	// CLSID_WbemLocator {4590F811-1D3A-11D0-891F-00AA004B2E24}
	clsidWbemLocator = guid{0x4590F811, 0x1D3A, 0x11D0, [8]byte{0x89, 0x1F, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}}
	// IID_IWbemLocator {DC12A687-737F-11CF-884D-00AA004B2E24}
	iidWbemLocator = guid{0xDC12A687, 0x737F, 0x11CF, [8]byte{0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24}}
)

const (
	coinitMultithreaded = 0x0
	clsctxInprocServer  = 0x1

	rpcCAuthnLevelDefault   = 0
	rpcCAuthnLevelCall      = 3
	rpcCImpLevelImpersonate = 3
	rpcCAuthnWinNT          = 10
	rpcCAuthzNone           = 0
	eoacNone                = 0

	wbemFlagForwardOnly       = 0x20
	wbemFlagReturnImmediately = 0x10
	wbemInfinite              = 0xFFFFFFFF

	// HRESULTs we treat specially.
	sOK               = 0
	sFalse            = 1
	rpcEChangedMode   = 0x80010106
	wbemEInvalidNS    = 0x8004100E // WBEM_E_INVALID_NAMESPACE
	wbemENotSupported = 0x80041024 // the namespace doesn't carry these classes

	// IUnknown / interface vtable slots.
	idxRelease       = 2
	idxConnectServer = 3  // IWbemLocator
	idxExecQuery     = 20 // IWbemServices
	idxEnumNext      = 4  // IEnumWbemClassObject
	idxObjGet        = 4  // IWbemClassObject

	// VARTYPEs we read (other types decode to "").
	vtI2   = 2
	vtI4   = 3
	vtBStr = 8
	vtBool = 11
	vtUI2  = 18
	vtUI4  = 19
	vtInt  = 22
	vtUInt = 23

	wmiMaxRows = 4096 // safety cap per query
)

var (
	modole32                 = syscall.NewLazyDLL("ole32.dll")
	procCoInitializeEx       = modole32.NewProc("CoInitializeEx")
	procCoUninitialize       = modole32.NewProc("CoUninitialize")
	procCoInitializeSecurity = modole32.NewProc("CoInitializeSecurity")
	procCoCreateInstance     = modole32.NewProc("CoCreateInstance")
	procCoSetProxyBlanket    = modole32.NewProc("CoSetProxyBlanket")

	modoleaut32        = syscall.NewLazyDLL("oleaut32.dll")
	procSysAllocString = modoleaut32.NewProc("SysAllocString")
	procSysFreeString  = modoleaut32.NewProc("SysFreeString")
	procSysStringLen   = modoleaut32.NewProc("SysStringLen")
	procVariantInit    = modoleaut32.NewProc("VariantInit")
	procVariantClear   = modoleaut32.NewProc("VariantClear")
)

// variant mirrors the Win32 VARIANT. The union is one machine word (val) plus
// padding, which makes the struct 16 bytes on 386 and 24 on amd64/arm64 — the
// real VARIANT size on each — so the layout is correct without arch-specific
// code.
type variant struct {
	vt  uint16
	w1  uint16
	w2  uint16
	w3  uint16
	val uintptr
	_   uintptr
}

// comCall dispatches method (a vtable slot) on a COM interface pointer.
func comCall(obj unsafe.Pointer, method int, a ...uintptr) uintptr {
	vtbl := *(*unsafe.Pointer)(obj)
	fn := *(*uintptr)(unsafe.Pointer(uintptr(vtbl) + uintptr(method)*unsafe.Sizeof(uintptr(0))))
	args := make([]uintptr, 1, len(a)+1)
	args[0] = uintptr(obj)
	args = append(args, a...)
	r, _, _ := syscall.SyscallN(fn, args...)
	return r
}

func release(obj unsafe.Pointer) {
	if obj != nil {
		comCall(obj, idxRelease)
	}
}

// sysBSTR allocates a BSTR (freed with sysFree).
func sysBSTR(s string) uintptr {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		return 0
	}
	r, _, _ := procSysAllocString.Call(uintptr(unsafe.Pointer(p)))
	return r
}

func sysFree(b uintptr) {
	if b != 0 {
		procSysFreeString.Call(b)
	}
}

// bstrString reads a BSTR (a length-prefixed UTF-16 string) into a Go string.
func bstrString(b unsafe.Pointer) string {
	if b == nil {
		return ""
	}
	n, _, _ := procSysStringLen.Call(uintptr(b))
	if n == 0 {
		return ""
	}
	return string(utf16.Decode(unsafe.Slice((*uint16)(b), int(n))))
}

// variantString renders the property types WMI returns for the fields we read
// (strings, a few integers, booleans) as text; other types yield "".
func variantString(v *variant) string {
	switch v.vt {
	case vtBStr:
		// Reinterpret the union word as a pointer without a uintptr→Pointer
		// conversion, so go vet's unsafeptr check stays satisfied.
		return bstrString(*(*unsafe.Pointer)(unsafe.Pointer(&v.val)))
	case vtI4, vtUI4, vtInt, vtUInt:
		return fmt.Sprintf("%d", int32(uint32(v.val)))
	case vtI2, vtUI2:
		return fmt.Sprintf("%d", int16(uint16(v.val)))
	case vtBool:
		if uint16(v.val) != 0 {
			return "true"
		}
		return "false"
	default: // vtEmpty, vtNull, arrays, objects
		return ""
	}
}

// withWMI connects to a CIM namespace over COM and runs fn against the
// resulting IWbemServices pointer. COM apartments are per-thread, so the whole
// exchange is pinned to one OS thread.
func withWMI(namespace string, fn func(svc unsafe.Pointer) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hr, _, _ := procCoInitializeEx.Call(0, coinitMultithreaded)
	switch hr {
	case sOK, sFalse:
		defer procCoUninitialize.Call()
	case rpcEChangedMode:
		// COM is already up on this thread in another mode; use it, don't tear
		// it down.
	default:
		return fmt.Errorf("CoInitializeEx: 0x%08x", uint32(hr))
	}

	// Process-wide security; only the first call in the process takes effect,
	// later ones return RPC_E_TOO_LATE, which is fine.
	procCoInitializeSecurity.Call(0, ^uintptr(0), 0, 0, rpcCAuthnLevelDefault, rpcCImpLevelImpersonate, 0, eoacNone, 0)

	var loc unsafe.Pointer
	rc, _, _ := procCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidWbemLocator)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidWbemLocator)), uintptr(unsafe.Pointer(&loc)))
	if rc != sOK || loc == nil {
		return fmt.Errorf("CoCreateInstance(WbemLocator): 0x%08x", uint32(rc))
	}
	defer release(loc)

	bNS := sysBSTR(namespace)
	defer sysFree(bNS)
	var svc unsafe.Pointer
	rc = comCall(loc, idxConnectServer, bNS, 0, 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&svc)))
	if rc != sOK || svc == nil {
		return fmt.Errorf("ConnectServer(%s): 0x%08x", namespace, uint32(rc))
	}
	defer release(svc)

	// Set the proxy security so the service honours our identity. A failure
	// here isn't fatal for a local namespace, so it's not reported.
	procCoSetProxyBlanket.Call(uintptr(svc), rpcCAuthnWinNT, rpcCAuthzNone, 0,
		rpcCAuthnLevelCall, rpcCImpLevelImpersonate, 0, eoacNone)

	return fn(svc)
}

// queryInto runs a WQL query and returns one map of the requested properties
// per instance.
func queryInto(svc unsafe.Pointer, wql string, props []string) ([]map[string]string, error) {
	bLang := sysBSTR("WQL")
	defer sysFree(bLang)
	bQuery := sysBSTR(wql)
	defer sysFree(bQuery)

	var enum unsafe.Pointer
	hr := comCall(svc, idxExecQuery, bLang, bQuery,
		wbemFlagForwardOnly|wbemFlagReturnImmediately, 0, uintptr(unsafe.Pointer(&enum)))
	if hr != sOK || enum == nil {
		return nil, fmt.Errorf("ExecQuery(%s): 0x%08x", wql, uint32(hr))
	}
	defer release(enum)

	names := make([]*uint16, len(props))
	for i, p := range props {
		names[i], _ = syscall.UTF16PtrFromString(p)
	}

	var rows []map[string]string
	for len(rows) < wmiMaxRows {
		var obj unsafe.Pointer
		var returned uint32
		hr := comCall(enum, idxEnumNext, uintptr(wbemInfinite), 1,
			uintptr(unsafe.Pointer(&obj)), uintptr(unsafe.Pointer(&returned)))
		if hr != sOK || returned == 0 || obj == nil {
			break // WBEM_S_FALSE and returned==0 at the end of the enumeration
		}
		row := make(map[string]string, len(props))
		for i, p := range props {
			var v variant
			procVariantInit.Call(uintptr(unsafe.Pointer(&v)))
			g := comCall(obj, idxObjGet, uintptr(unsafe.Pointer(names[i])), 0,
				uintptr(unsafe.Pointer(&v)), 0, 0)
			if g == sOK {
				if s := strings.TrimRight(variantString(&v), "\x00"); s != "" {
					row[p] = s
				}
			}
			procVariantClear.Call(uintptr(unsafe.Pointer(&v)))
		}
		release(obj)
		rows = append(rows, row)
	}
	return rows, nil
}

// wmiQuery is the one-shot form used by tests and simple callers.
func wmiQuery(namespace, wql string, props []string) ([]map[string]string, error) {
	var rows []map[string]string
	err := withWMI(namespace, func(svc unsafe.Pointer) error {
		r, e := queryInto(svc, wql, props)
		rows = r
		return e
	})
	return rows, err
}

var (
	filterProps   = []string{"Name", "Query", "QueryLanguage", "EventNamespace"}
	consumerProps = []string{"__CLASS", "Name", "CommandLineTemplate", "ExecutablePath",
		"WorkingDirectory", "ScriptingEngine", "ScriptText", "ScriptFileName", "Filename", "Destination"}
	bindingProps = []string{"Filter", "Consumer"}
	timerProps   = []string{"__CLASS", "TimerId", "IntervalBetweenEvents", "EventDateTime", "SkipIfPassed"}
)

func collectWMI(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("wmi")
	// root\subscription is where permanent subscriptions live; root\default was
	// used by some older malware. A namespace that rejects these classes is
	// normal, not an error.
	namespaces := []string{`ROOT\subscription`, `ROOT\default`}
	total := 0
	for _, ns := range namespaces {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		err := withWMI(ns, func(svc unsafe.Pointer) error {
			return collectWMINamespace(ctx, res, svc, ns, opts, &total)
		})
		if err != nil {
			// root\default is the optional legacy location, and a namespace that
			// doesn't carry the subscription classes is not an error worth
			// raising — both are expected on some hosts.
			tolerable := ns == `ROOT\default` ||
				strings.Contains(err.Error(), fmt.Sprintf("%08x", uint32(wbemEInvalidNS))) ||
				strings.Contains(err.Error(), fmt.Sprintf("%08x", uint32(wbemENotSupported)))
			if tolerable {
				res.SetMeta("note_"+strings.ToLower(ns), err.Error())
			} else {
				res.Fail(ns + ": " + err.Error())
			}
		}
	}
	res.SetMeta("subscription_object_count", total)
	if total == 0 {
		res.SetMeta("note", "no WMI permanent event subscriptions found (the clean-host default)")
	}
	return res.Finish(), nil
}

// collectWMINamespace reads the filters, consumers and bindings in one
// namespace, judges them and adds the records.
func collectWMINamespace(ctx context.Context, res *Result, svc unsafe.Pointer, ns string, opts RunOptions, total *int) error {
	// Consumers first, so bindings can be ranked by the consumer they bind to.
	crows, err := queryInto(svc, "SELECT * FROM __EventConsumer", consumerProps)
	if err != nil {
		return err
	}
	byKey := map[string]*wmiConsumer{}
	for _, r := range crows {
		if ctx.Err() != nil {
			break
		}
		c := wmiConsumer{
			Namespace: ns, Class: r["__CLASS"], Name: r["Name"],
			CommandLineTemplate: r["CommandLineTemplate"], ExecutablePath: r["ExecutablePath"],
			WorkingDirectory: r["WorkingDirectory"], ScriptingEngine: r["ScriptingEngine"],
			ScriptText: r["ScriptText"], ScriptFileName: r["ScriptFileName"],
			Extra: firstNonEmpty(r["Destination"], r["Filename"]),
		}
		cc := c
		byKey[consumerKey(c.Class, c.Name)] = &cc
		res.Add(wmiConsumerFields(ctx, c, opts), judgeWMIConsumer(c)...)
		*total++
	}

	frows, err := queryInto(svc, "SELECT * FROM __EventFilter", filterProps)
	if err != nil {
		return err
	}
	for _, r := range frows {
		f := wmiFilter{Namespace: ns, Name: r["Name"], Query: r["Query"],
			QueryLang: r["QueryLanguage"], EventNamespace: r["EventNamespace"]}
		fields := map[string]any{"kind": "filter", "namespace": ns, "name": f.Name, "query": f.Query}
		if f.QueryLang != "" {
			fields["query_language"] = f.QueryLang
		}
		if f.EventNamespace != "" {
			fields["event_namespace"] = f.EventNamespace
		}
		res.Add(fields, judgeWMIFilter(f)...)
		*total++
	}

	brows, err := queryInto(svc, "SELECT * FROM __FilterToConsumerBinding", bindingProps)
	if err != nil {
		return err
	}
	for _, r := range brows {
		b := wmiBinding{Namespace: ns, Filter: r["Filter"], Consumer: r["Consumer"]}
		class, name := parseWMIRef(b.Consumer)
		matched := byKey[consumerKey(class, name)]
		fields := map[string]any{"kind": "binding", "namespace": ns, "filter": b.Filter, "consumer": b.Consumer}
		res.Add(fields, judgeWMIBinding(b, matched)...)
		*total++
	}

	// Timer instructions — the schedule half of timer-based subscriptions. A
	// clean host carries none; a namespace that doesn't carry the class is
	// expected, so a query failure here is noted rather than failing the
	// namespace (the subscription records above are the important ones).
	trows, terr := queryInto(svc, "SELECT * FROM __TimerInstruction", timerProps)
	if terr != nil {
		res.SetMeta("note_timer_"+strings.ToLower(ns), terr.Error())
		return nil
	}
	for _, r := range trows {
		if ctx.Err() != nil {
			break
		}
		tm := wmiTimer{Namespace: ns, Class: r["__CLASS"], TimerID: r["TimerId"],
			Interval: r["IntervalBetweenEvents"], When: r["EventDateTime"], SkipIfPassed: r["SkipIfPassed"]}
		fields := map[string]any{"kind": "timer", "namespace": ns, "class": tm.Class}
		if tm.TimerID != "" {
			fields["timer_id"] = tm.TimerID
		}
		if tm.Interval != "" {
			fields["interval_ms"] = tm.Interval
		}
		if tm.When != "" {
			fields["event_datetime"] = tm.When
		}
		if tm.SkipIfPassed != "" {
			fields["skip_if_passed"] = tm.SkipIfPassed
		}
		res.Add(fields, judgeWMITimer(tm)...)
		*total++
	}
	return nil
}

// wmiConsumerFields builds the record fields for one consumer and hashes the
// on-disk payload a consumer points at, where there is one.
func wmiConsumerFields(ctx context.Context, c wmiConsumer, opts RunOptions) map[string]any {
	fields := map[string]any{"kind": "consumer", "namespace": c.Namespace, "class": c.Class, "name": c.Name}
	put := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			fields[k] = v
		}
	}
	put("command_line_template", c.CommandLineTemplate)
	put("executable_path", c.ExecutablePath)
	put("working_directory", c.WorkingDirectory)
	put("scripting_engine", c.ScriptingEngine)
	put("script_text", c.ScriptText)
	put("script_file_name", c.ScriptFileName)
	put("destination", c.Extra)

	if opts.Hasher != nil && ctx.Err() == nil {
		img := ""
		switch {
		case c.ExecutablePath != "":
			img = c.ExecutablePath
		case c.CommandLineTemplate != "":
			img = imageFromCommand(c.CommandLineTemplate)
		case c.ScriptFileName != "":
			img = c.ScriptFileName
		}
		if strings.ContainsAny(img, `\/`) {
			opts.Hasher.Fields(ctx, fields, "payload", normalizeImage(img))
		}
	}
	return fields
}
