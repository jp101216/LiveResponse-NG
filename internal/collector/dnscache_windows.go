//go:build windows

package collector

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/jp101216/liveresponse-ng/internal/aidetect"
)

var (
	moddnsapi                = syscall.NewLazyDLL("dnsapi.dll")
	procDnsGetCacheDataTable = moddnsapi.NewProc("DnsGetCacheDataTable")
	procDnsQueryW            = moddnsapi.NewProc("DnsQuery_W")
	procDnsRecordListFree    = moddnsapi.NewProc("DnsRecordListFree")
)

// dnsCacheEntry mirrors the (undocumented) DNS_CACHE_ENTRY. Only these
// fields are read, through the pointer, never by copying the struct.
type dnsCacheEntry struct {
	Next       *dnsCacheEntry
	Name       *uint16
	Type       uint16
	DataLength uint16
	Flags      uint32
}

// dnsRecordW mirrors the head of DNS_RECORDW (documented). Data is the start
// of the type-specific union; only the bytes a record actually carries
// (4 for A, 16 for AAAA) are ever read, because Windows allocates each record
// at its real size, which can be smaller than this struct.
type dnsRecordW struct {
	Next       *dnsRecordW
	Name       *uint16
	Type       uint16
	DataLength uint16
	Flags      uint32
	TTL        uint32
	Reserved   uint32
	Data       [16]byte
}

const (
	dnsTypeA             = 1
	dnsTypeCNAME         = 5
	dnsTypeAAAA          = 28
	dnsQueryNoWireQuery  = 0x10 // DNS_QUERY_NO_WIRE_QUERY: answer from the local cache only
	dnsFreeRecordList    = 1    // DNS_FREE_TYPE DnsFreeRecordList
	maxDNSCacheEntries   = 200000
	maxDNSCacheLookups   = 5000
	dnsSnapshotMaxWait   = 15 * time.Second
	dnsMaxNamesPerRecord = 8
)

// dnsCacheName is one cached name with its record types and addresses.
type dnsCacheName struct {
	Name  string
	Types []uint16
	Addrs []netip.Addr
}

// dnsSnapshot is the resolver cache as read once per run.
type dnsSnapshot struct {
	TakenAt   time.Time
	Done      time.Time
	Names     []dnsCacheName // sorted by name
	byAddr    map[netip.Addr][]string
	Lookups   int
	Truncated bool
	Err       error
}

var (
	dnsSnapOnce sync.Once
	dnsSnap     *dnsSnapshot
)

// snapshotDNSCache reads the cache exactly once per run, whichever collector
// asks first.
func snapshotDNSCache() *dnsSnapshot {
	dnsSnapOnce.Do(func() { dnsSnap = readDNSCache() })
	return dnsSnap
}

// waitDNSSnapshot takes (or waits for) the snapshot, but never longer than
// max: a wedged DNS Client service must not take the network collector down
// with it.
func waitDNSSnapshot(ctx context.Context, max time.Duration) (*dnsSnapshot, error) {
	done := make(chan *dnsSnapshot, 1)
	go func() { done <- snapshotDNSCache() }()
	select {
	case s := <-done:
		if s.Err != nil {
			return s, s.Err
		}
		return s, nil
	case <-time.After(max):
		return nil, fmt.Errorf("DNS cache read did not finish within %s", max)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// dnsNamesByAddr returns cached hostnames per address for correlation.
func dnsNamesByAddr(ctx context.Context) (map[netip.Addr][]string, error) {
	s, err := waitDNSSnapshot(ctx, dnsSnapshotMaxWait)
	if err != nil {
		return nil, err
	}
	return s.byAddr, nil
}

func readDNSCache() *dnsSnapshot {
	s := &dnsSnapshot{TakenAt: time.Now().UTC(), byAddr: map[netip.Addr][]string{}}
	defer func() { s.Done = time.Now().UTC() }()
	if err := procDnsGetCacheDataTable.Find(); err != nil {
		s.Err = fmt.Errorf("DnsGetCacheDataTable unavailable: %w", err)
		return s
	}
	var head *dnsCacheEntry
	r, _, _ := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head)))
	if r == 0 {
		s.Err = errors.New("DnsGetCacheDataTable failed (DNS Client service stopped?)")
		return s
	}

	byName := map[string]*dnsCacheName{}
	var order []string
	count := 0
	for e := head; e != nil; e = e.Next {
		if count++; count > maxDNSCacheEntries {
			s.Truncated = true
			break
		}
		name := strings.ToLower(utf16PtrToString(e.Name))
		if name == "" {
			continue
		}
		n, ok := byName[name]
		if !ok {
			n = &dnsCacheName{Name: name}
			byName[name] = n
			order = append(order, name)
		}
		n.Types = appendUnique16(n.Types, e.Type)
	}

	for _, name := range order {
		n := byName[name]
		for _, qt := range queryTypesFor(n.Types) {
			if s.Lookups >= maxDNSCacheLookups {
				s.Truncated = true
				break
			}
			s.Lookups++
			for _, a := range cachedAddresses(name, qt) {
				if !containsAddr(n.Addrs, a) {
					n.Addrs = append(n.Addrs, a)
				}
			}
		}
		for _, a := range n.Addrs {
			s.byAddr[a] = appendUniqueStr(s.byAddr[a], name)
		}
	}
	sort.Strings(order)
	s.Names = make([]dnsCacheName, 0, len(order))
	for _, name := range order {
		s.Names = append(s.Names, *byName[name])
	}
	return s
}

// queryTypesFor picks the address queries worth asking the cache for.
func queryTypesFor(types []uint16) []uint16 {
	var out []uint16
	for _, t := range types {
		switch t {
		case dnsTypeA, dnsTypeCNAME:
			out = appendUnique16(out, dnsTypeA)
		case dnsTypeAAAA:
			out = appendUnique16(out, dnsTypeAAAA)
		}
	}
	return out
}

// cachedAddresses asks the resolver cache — DNS_QUERY_NO_WIRE_QUERY, so
// nothing goes on the network — for a name's A or AAAA answers.
func cachedAddresses(name string, qtype uint16) []netip.Addr {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil
	}
	var rec *dnsRecordW
	st, _, _ := procDnsQueryW.Call(uintptr(unsafe.Pointer(p)), uintptr(qtype), dnsQueryNoWireQuery,
		0, uintptr(unsafe.Pointer(&rec)), 0)
	if st != 0 || rec == nil {
		return nil
	}
	defer procDnsRecordListFree.Call(uintptr(unsafe.Pointer(rec)), dnsFreeRecordList)
	var out []netip.Addr
	for r, n := rec, 0; r != nil && n < 256; r, n = r.Next, n+1 {
		switch {
		case r.Type == dnsTypeA && r.DataLength >= 4:
			out = append(out, netip.AddrFrom4([4]byte{r.Data[0], r.Data[1], r.Data[2], r.Data[3]}))
		case r.Type == dnsTypeAAAA && r.DataLength >= 16:
			var b [16]byte
			copy(b[:], r.Data[:16])
			out = append(out, netip.AddrFrom16(b).Unmap())
		}
	}
	return out
}

func collectDNSCache(ctx context.Context, opts RunOptions) (Result, error) {
	res := NewResult("dnscache")
	res.SetMeta("note", "reads the resolver cache via the undocumented DnsGetCacheDataTable API; "+
		"addresses come from cache-only lookups (DNS_QUERY_NO_WIRE_QUERY), nothing is sent on the network")

	s, err := waitDNSSnapshot(ctx, dnsSnapshotMaxWait*2)
	if err != nil {
		return res.Finish(), err
	}
	res.SetMeta("taken_at", s.TakenAt)
	res.SetMeta("name_count", len(s.Names))
	res.SetMeta("cache_lookups", s.Lookups)
	if s.Truncated {
		res.Fail(fmt.Sprintf("cache larger than the read limits (%d entries / %d lookups); snapshot truncated",
			maxDNSCacheEntries, maxDNSCacheLookups))
	}
	polluted := snapshotPolluted(s.Done)
	res.SetMeta("taken_before_module_a_lookups", !polluted)

	for _, n := range s.Names {
		if err := ctx.Err(); err != nil {
			res.Fail("cancelled: " + err.Error())
			break
		}
		types := make([]string, len(n.Types))
		for i, t := range n.Types {
			types[i] = dnsTypeName(t)
		}
		fields := map[string]any{"name": n.Name, "types": types}
		if len(n.Addrs) > 0 {
			addrs := make([]string, len(n.Addrs))
			for i, a := range n.Addrs {
				addrs[i] = a.String()
			}
			fields["addresses"] = addrs
		}
		var findings []Finding
		if how, ok := aidetect.MatchHostname(n.Name); ok {
			fields["llm_provider"] = true
			if !polluted {
				findings = append(findings, Finding{
					Rule: "ai.llm_dns_cache", Severity: SevNotable, Technique: "T1071.001", Confidence: 40,
					Detail: fmt.Sprintf("this host resolved LLM inference endpoint %s (%s) recently enough to still be cached; "+
						"correlate with the network collector and process start times", n.Name, how),
				})
			}
		}
		res.Add(fields, findings...)
	}
	return res.Finish(), nil
}

func appendUnique16(s []uint16, v uint16) []uint16 {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func appendUniqueStr(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func containsAddr(s []netip.Addr, a netip.Addr) bool {
	for _, x := range s {
		if x == a {
			return true
		}
	}
	return false
}
