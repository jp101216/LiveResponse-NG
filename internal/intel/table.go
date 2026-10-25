package intel

// table.go — longest-prefix-match lookup by prefix length.
//
// IP longest-prefix match has well-known heavyweight structures (LC-tries,
// Patricia trees). They aren't needed here: a per-length hash table is simpler,
// obviously correct, and memory-proportional to the number of prefixes (one map
// entry each), not to the number of address bits — which matters because a
// refreshed dataset can hold hundreds of thousands of prefixes.
//
// The idea: bucket prefixes by their length, keyed by their (masked) network
// address. To look an address up, try the lengths present in the dataset from
// longest to shortest; the first bucket whose masked key matches is, by
// construction, the most specific prefix containing the address. That is at most
// 33 map probes for IPv4 and 129 for IPv6 — constant with respect to dataset
// size. Byte-array keys ([4]byte / [16]byte) are comparable, so they're used as
// map keys directly, with no hashing of our own.

// table4 is the IPv4 LPM table; table6 is its IPv6 twin. They are kept as two
// concrete types rather than one generic so the bit-masking stays explicit.
type table4 struct {
	byLen map[int]map[[4]byte]int32
	lens  []int // prefix lengths present, descending (set by finish)
}

type table6 struct {
	byLen map[int]map[[16]byte]int32
	lens  []int
}

func (t *table4) insert(net [4]byte, bits int, idx int32) {
	if t.byLen == nil {
		t.byLen = map[int]map[[4]byte]int32{}
	}
	m := t.byLen[bits]
	if m == nil {
		m = map[[4]byte]int32{}
		t.byLen[bits] = m
		t.lens = append(t.lens, bits)
	}
	m[net] = idx
}

func (t *table4) finish() { t.lens = sortDescUnique(t.lens) }

func (t *table4) lookup(addr [4]byte) int32 {
	for _, l := range t.lens {
		if idx, ok := t.byLen[l][mask4(addr, l)]; ok {
			return idx
		}
	}
	return -1
}

func (t *table6) insert(net [16]byte, bits int, idx int32) {
	if t.byLen == nil {
		t.byLen = map[int]map[[16]byte]int32{}
	}
	m := t.byLen[bits]
	if m == nil {
		m = map[[16]byte]int32{}
		t.byLen[bits] = m
		t.lens = append(t.lens, bits)
	}
	m[net] = idx
}

func (t *table6) finish() { t.lens = sortDescUnique(t.lens) }

func (t *table6) lookup(addr [16]byte) int32 {
	for _, l := range t.lens {
		if idx, ok := t.byLen[l][mask6(addr, l)]; ok {
			return idx
		}
	}
	return -1
}

// mask4 zeroes all but the top bits of a 4-byte address.
func mask4(a [4]byte, bits int) [4]byte {
	if bits <= 0 {
		return [4]byte{}
	}
	if bits >= 32 {
		return a
	}
	full := bits / 8
	rem := bits % 8
	var out [4]byte
	copy(out[:full], a[:full])
	if rem != 0 {
		out[full] = a[full] & byte(0xff<<(8-rem))
	}
	return out
}

// mask6 zeroes all but the top bits of a 16-byte address.
func mask6(a [16]byte, bits int) [16]byte {
	if bits <= 0 {
		return [16]byte{}
	}
	if bits >= 128 {
		return a
	}
	full := bits / 8
	rem := bits % 8
	var out [16]byte
	copy(out[:full], a[:full])
	if rem != 0 {
		out[full] = a[full] & byte(0xff<<(8-rem))
	}
	return out
}
