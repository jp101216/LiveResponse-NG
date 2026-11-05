//go:build windows

package collector

import (
	"context"
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// Only the prefix through action is read. It avoids the architecture-specific
// UINT64/GUID context union later in FWPM_FILTER0. All union values in this
// prefix have pointer alignment on both Windows 32-bit and 64-bit.
type wfpDisplay struct{ Name, Description *uint16 }
type wfpBlob struct {
	Size uint32
	Data *byte
}
type wfpValue struct {
	Type  uint32
	Value unsafe.Pointer
}
type wfpCondition struct {
	Key   syscall.GUID
	Match uint32
	Value wfpValue
}
type wfpAction struct {
	Type uint32
	Key  syscall.GUID
}
type wfpFilterPrefix struct {
	Key             syscall.GUID
	Display         wfpDisplay
	Flags           uint32
	Provider        *syscall.GUID
	ProviderData    wfpBlob
	Layer, SubLayer syscall.GUID
	Weight          wfpValue
	Count           uint32
	Conditions      *wfpCondition
	Action          wfpAction
}
type wfpProviderPrefix struct {
	Key     syscall.GUID
	Display wfpDisplay
}

var (
	wfpDLL         = syscall.NewLazyDLL("fwpuclnt.dll")
	wfpOpen        = wfpDLL.NewProc("FwpmEngineOpen0")
	wfpClose       = wfpDLL.NewProc("FwpmEngineClose0")
	wfpCreateEnum  = wfpDLL.NewProc("FwpmFilterCreateEnumHandle0")
	wfpDestroyEnum = wfpDLL.NewProc("FwpmFilterDestroyEnumHandle0")
	wfpEnum        = wfpDLL.NewProc("FwpmFilterEnum0")
	wfpFree        = wfpDLL.NewProc("FwpmFreeMemory0")
	wfpGetProvider = wfpDLL.NewProc("FwpmProviderGetByKey0")
	wfpAppID       = syscall.GUID{Data1: 0xd78e1e87, Data2: 0x8644, Data3: 0x4ea5, Data4: [8]byte{0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}}
	wfpConnect4    = syscall.GUID{Data1: 0xc38d57d1, Data2: 0x05a7, Data3: 0x4c33, Data4: [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	wfpConnect6    = syscall.GUID{Data1: 0x4a72393b, Data2: 0x319f, Data3: 0x44bc, Data4: [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
)

type wfpCollector struct{}

func (*wfpCollector) Name() string        { return "wfp" }
func (*wfpCollector) Platforms() []string { return []string{"windows"} }
func (*wfpCollector) Collect(ctx context.Context) (Result, error) {
	r := NewResult("wfp")
	r.SetMeta("coverage", "read-only BFE enumeration of enabled app-specific BLOCK filters; not a packet test or effective-policy evaluation; filters without app IDs, callouts and other agent names are not classified")
	for _, p := range []*syscall.LazyProc{wfpOpen, wfpClose, wfpCreateEnum, wfpDestroyEnum, wfpEnum, wfpFree, wfpGetProvider} {
		if err := p.Find(); err != nil {
			return r.Finish(), err
		}
	}
	var engine, enumerator uintptr
	if status, _, _ := wfpOpen.Call(0, 10, 0, 0, uintptr(unsafe.Pointer(&engine))); status != 0 {
		return r.Finish(), fmt.Errorf("FwpmEngineOpen0: %w", syscall.Errno(status))
	}
	defer wfpClose.Call(engine)
	if status, _, _ := wfpCreateEnum.Call(engine, 0, uintptr(unsafe.Pointer(&enumerator))); status != 0 {
		return r.Finish(), fmt.Errorf("FwpmFilterCreateEnumHandle0: %w", syscall.Errno(status))
	}
	defer wfpDestroyEnum.Call(engine, enumerator)
	providers := map[syscall.GUID]string{}
	providerName := func(key *syscall.GUID) string {
		if key == nil {
			return ""
		}
		if name, ok := providers[*key]; ok {
			return name
		}
		var p *wfpProviderPrefix
		name := ""
		if status, _, _ := wfpGetProvider.Call(engine, uintptr(unsafe.Pointer(key)), uintptr(unsafe.Pointer(&p))); status == 0 && p != nil {
			name = excerpt(redactSecrets(utf16PtrToString(p.Display.Name)), 256)
			wfpFree.Call(uintptr(unsafe.Pointer(&p)))
		}
		providers[*key] = name
		return name
	}
	const maxFilters = 16384
	scanned, invalid := 0, 0
	complete := false
	recordLimit := false
	for scanned < maxFilters && ctx.Err() == nil {
		var entries **wfpFilterPrefix
		var count uint32
		status, _, _ := wfpEnum.Call(engine, enumerator, 128, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&count)))
		if status != 0 {
			if entries != nil {
				wfpFree.Call(uintptr(unsafe.Pointer(&entries)))
			}
			r.Fail(fmt.Sprintf("FwpmFilterEnum0: %v", syscall.Errno(status)))
			break
		}
		if count > 128 || (count > 0 && entries == nil) {
			r.Fail("WFP returned an invalid enumeration page")
			if entries != nil {
				wfpFree.Call(uintptr(unsafe.Pointer(&entries)))
			}
			break
		}
		if count == 0 {
			complete = true
			if entries != nil {
				wfpFree.Call(uintptr(unsafe.Pointer(&entries)))
			}
			break
		}
		for _, f := range unsafe.Slice(entries, int(count)) {
			if ctx.Err() != nil || recordLimit {
				break
			}
			scanned++
			if f == nil {
				invalid++
				continue
			}
			// FWP_ACTION_BLOCK=0x1001; FWPM_FILTER_FLAG_DISABLED=0x20.
			if f.Action.Type != 0x1001 || f.Flags&0x20 != 0 {
				continue
			}
			if f.Count > 256 || (f.Count > 0 && f.Conditions == nil) {
				invalid++
				continue
			}
			layer := guidText(f.Layer)
			if f.Layer == wfpConnect4 {
				layer = "ale_auth_connect_v4"
			}
			if f.Layer == wfpConnect6 {
				layer = "ale_auth_connect_v6"
			}
			var conditions []map[string]any
			for _, c := range unsafe.Slice(f.Conditions, int(f.Count)) {
				conditions = append(conditions, map[string]any{"field": guidText(c.Key), "match_type": c.Match, "value_type": c.Value.Type})
			}
			for _, c := range unsafe.Slice(f.Conditions, int(f.Count)) {
				if len(r.Records) >= 4096 {
					recordLimit = true
					break
				}
				if c.Key != wfpAppID || c.Value.Type != 12 || c.Value.Value == nil {
					continue
				}
				app, ok := wfpAppPath((*wfpBlob)(c.Value.Value))
				if !ok {
					invalid++
					continue
				}
				match := "other"
				if c.Match == 0 {
					match = "equal"
				}
				fields := map[string]any{"filter_key": guidText(f.Key), "name": excerpt(redactSecrets(utf16PtrToString(f.Display.Name)), 256),
					"layer": layer, "sublayer": guidText(f.SubLayer), "action": "block", "flags": f.Flags, "persistent": f.Flags&1 != 0,
					"app_path": app, "app_match": match, "condition_count": f.Count, "conditions": conditions}
				if f.Provider != nil {
					fields["provider_key"] = guidText(*f.Provider)
					fields["provider_name"] = providerName(f.Provider)
				}
				r.Add(fields, wfpFilterFindings(app, layer, match)...)
			}
		}
		wfpFree.Call(uintptr(unsafe.Pointer(&entries)))
		if recordLimit {
			r.Fail("WFP record limit reached; enumeration incomplete")
			break
		}
	}
	if ctx.Err() != nil {
		r.Fail("WFP enumeration cancelled: " + ctx.Err().Error())
	}
	if !complete && scanned >= maxFilters {
		r.Fail("WFP filter limit reached; enumeration incomplete")
	}
	if invalid > 0 {
		r.Fail(fmt.Sprintf("%d invalid or oversized WFP fields omitted", invalid))
	}
	r.SetMeta("filters_scanned", scanned)
	r.SetMeta("enumeration_complete", complete)
	return r.Finish(), nil
}

func wfpAppPath(blob *wfpBlob) (string, bool) {
	if blob == nil || blob.Data == nil || blob.Size < 2 || blob.Size > 65536 || blob.Size%2 != 0 {
		return "", false
	}
	b := unsafe.Slice(blob.Data, int(blob.Size))
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	// FWP_BYTE_BLOB supplies an explicit byte length. Tolerate both API-
	// terminated strings and length-delimited UTF-16 without a terminator.
	if u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	if len(u) == 0 {
		return "", false
	}
	for _, v := range u {
		if v == 0 {
			return "", false
		}
	}
	return string(utf16.Decode(u)), true
}

func guidText(g syscall.GUID) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

func init() { Register(func() Collector { return &wfpCollector{} }) }
